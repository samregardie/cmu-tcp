#!/usr/bin/env python3
"""Data-path tests: loss, lost ACKs, and reordering.

Uses the fake-peer harness from test_cp1_handshake.py. A fake client
connects to tests/testing_server, which reads once and then sends
tests/random.input (10240 bytes, several packets). So:
  - to test the real *receiver*, the fake client sends data to the server;
  - to test the real *sender*, the fake client receives the server's data and
    chooses which packets to "lose" and what to ACK.

    python3 tests/test_cp1_data.py
"""

import os
import random
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_cp1_handshake import (  # noqa: E402
    ACK,
    CODE_DIR,
    FIN,
    HDR,
    SYN,
    T,
    FakePeer,
    check,
    check_interval,
    is_syn,
    is_synack,
    start,
    start_server,
)


def read_max_len():
    with open(os.path.join(CODE_DIR, "inc", "grading.h")) as f:
        m = re.search(r"#define\s+MAX_LEN\s+(\d+)", f.read())
    return int(m.group(1))


MAX_LEN = read_max_len()
MSS = MAX_LEN - HDR.size


def is_pure_ack(p):
    return p.flags == ACK and not p.payload


def connect():
    """Starts testing_server and handshakes. Returns (proc, peer, x, y)
    where x + 1 is our first data seq and y + 1 the server's."""
    proc, peer = start_server()
    x = 1000
    peer.send(x, 0, SYN)
    synack = peer.recv(T)
    check(synack is not None and is_synack(synack), "handshake failed")
    y = synack.seq
    peer.send(x + 1, y + 1, ACK)
    return proc, peer, x, y


def start_server_sending():
    """Connects and sends one data packet so testing_server starts sending
    random.input. Returns (proc, peer, next_seq, first_data_pkt)."""
    proc, peer, x, y = connect()
    peer.send(x + 1, y + 1, ACK, b"go")
    first = peer.recv_matching(lambda p: p.payload, T)
    check(first is not None, "server never started sending data")
    check(first.seq == y + 1, f"first data seq {first.seq}, want {y + 1}")
    return proc, peer, x + 1 + 2, first


def stop(proc, peer):
    proc.kill()
    proc.wait()
    peer.close()


# --------------------------------------------------------------------------
# Lost data packets
# --------------------------------------------------------------------------


def test_lost_data_retransmitted_until_received():
    """Sender: a lost data packet is resent on every timeout until ACKed."""
    proc, peer, my_seq, first = start_server_sending()
    try:
        prev = first
        for _ in range(2):  # "Lose" the original and one retransmission.
            again = peer.recv_matching(lambda p: p.seq == first.seq, 1.5 * T)
            check(again is not None, "lost data packet was not retransmitted")
            check_interval(prev, again, "data retransmissions")
            check(again.payload == first.payload, "retransmission changed")
            prev = again

        # Now it "arrives": ACK exactly that packet.
        first_end = first.seq + len(first.payload)
        peer.send(my_seq, first_end, ACK)
        extra = peer.recv_matching(lambda p: p.seq == first.seq, 1.5 * T)
        check(extra is None, "packet still retransmitted after its ACK")
    finally:
        stop(proc, peer)


def test_go_back_n_resends_everything_outstanding():
    """Sender: packets 1-2 ACKed, packet 3 lost. On timeout the sender resends
    packet 3 and every packet after it, and nothing before it."""
    proc, peer, my_seq, p1 = start_server_sending()
    try:
        sent = [p1]
        while True:  # Collect the rest of the burst.
            p = peer.recv_matching(lambda p: p.payload, 0.5)
            if p is None:
                break
            sent.append(p)
        sent.sort(key=lambda p: p.seq)
        check(len(sent) >= 4, f"server sent only {len(sent)} packets")
        end = {p.seq: p.seq + len(p.payload) for p in sent}

        # Packets 1-2 arrived; packet 3 was lost. ACK through packet 2.
        peer.send(my_seq, end[sent[1].seq], ACK)
        acked_at = time.monotonic()

        want = {p.seq for p in sent[2:]}
        got = []
        while True:
            p = peer.recv_matching(lambda p: p.payload, 1.5 * T)
            if p is None or (got and p.time - got[0].time > 0.5 * T):
                break
            got.append(p)
        check(got, "nothing retransmitted after timeout")
        gap = got[0].time - acked_at
        check(
            0.8 * T <= gap <= 1.5 * T,
            f"retransmission {gap:.2f}s after last ACK, want about {T:.2f}s",
        )
        seqs = {p.seq for p in got}
        early = seqs & {sent[0].seq, sent[1].seq}
        check(not early, "resent already-ACKed packet(s)")
        check(
            seqs == want,
            f"resent {len(seqs)} packets, want all {len(want)} outstanding",
        )
    finally:
        stop(proc, peer)


# --------------------------------------------------------------------------
# Large transfer
# --------------------------------------------------------------------------


def test_large_transfer_split_and_intact():
    """A 1 MB cmu_write is split into packets of at most MAX_LEN bytes and
    arrives intact, in order. The fake receiver ACKs in-order data."""
    size = 1024 * 1024
    data = random.Random(15441).randbytes(size)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name

    peer = FakePeer()
    env = dict(
        os.environ, server15441="127.0.0.1", serverport15441=str(peer.port)
    )
    proc = subprocess.Popen(
        [os.path.join(CODE_DIR, "tests", "bulk_sender"), path],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        syn = peer.recv(2 * T)
        check(syn is not None and is_syn(syn), "sender sent no SYN")
        y = 5000
        peer.send(y, syn.seq + 1, SYN | ACK)
        expected = syn.seq + 1
        received = bytearray()
        too_big = 0

        deadline = time.monotonic() + 60
        while len(received) < size and time.monotonic() < deadline:
            p = peer.recv(T)
            if p is None:
                continue
            if HDR.size + len(p.payload) > MAX_LEN:
                too_big += 1
            if p.payload and p.seq == expected:
                received += p.payload
                expected += len(p.payload)
            if p.payload:
                peer.send(y + 1, expected & 0xFFFFFFFF, ACK)

        check(too_big == 0, f"{too_big} packets larger than MAX_LEN")
        check(
            len(received) == size,
            f"received {len(received)} of {size} bytes",
        )
        check(bytes(received) == data, "received data differs from file")

        # ACK the sender's FIN (it uses one sequence number).
        fin = peer.recv_matching(lambda p: p.flags & FIN, 2 * T)
        check(fin is not None, "sender never sent a FIN")
        check(fin.seq == expected, f"FIN seq {fin.seq}, want {expected}")
        peer.send(y + 1, (fin.seq + 1) & 0xFFFFFFFF, ACK)
        try:
            proc.wait(timeout=T)
        except subprocess.TimeoutExpired:
            raise AssertionError("cmu_close did not return after all ACKed")
    finally:
        proc.kill()
        proc.wait()
        peer.close()
        os.unlink(path)


# --------------------------------------------------------------------------
# Lost ACKs
# --------------------------------------------------------------------------


def test_lost_ack_receiver_reacks_duplicate():
    """Receiver: if its ACK is lost and the data is resent, it ACKs again."""
    proc, peer, x, y = connect()
    try:
        payload = b"hello"
        want = x + 1 + len(payload)
        peer.send(x + 1, y + 1, ACK, payload)
        ack1 = peer.recv_matching(is_pure_ack, T)
        check(ack1 is not None, "no ACK for data")
        check(ack1.ack == want, f"ACK {ack1.ack}, want {want}")

        # Pretend ack1 was lost: resend the same data.
        peer.send(x + 1, y + 1, ACK, payload)
        ack2 = peer.recv_matching(is_pure_ack, T)
        check(ack2 is not None, "no re-ACK for duplicate data")
        check(ack2.ack == want, f"re-ACK {ack2.ack}, want {want}")
    finally:
        stop(proc, peer)


def test_lost_ack_covered_by_later_ack():
    """Sender: ACK for packet 1 lost, ACK for packet 2 arrives. Neither
    packet 1 nor 2 is retransmitted."""
    proc, peer, my_seq, p1 = start_server_sending()
    try:
        p2 = peer.recv_matching(
            lambda p: p.seq == p1.seq + len(p1.payload), T
        )
        check(p2 is not None, "server sent only one data packet")

        # ACK for p1 "lost"; send only the cumulative ACK covering p2.
        peer.send(my_seq, p2.seq + len(p2.payload), ACK)

        resent = peer.recv_matching(
            lambda p: p.seq in (p1.seq, p2.seq), 1.5 * T
        )
        check(resent is None, f"seq {resent and resent.seq} retransmitted")
    finally:
        stop(proc, peer)


# --------------------------------------------------------------------------
# Reordering
# --------------------------------------------------------------------------


def test_reordering_acks_only_cover_in_order_data():
    """Receiver: packets 2 then 1. The ACK after packet 2 must not move past
    the gap; after packet 1 it covers both."""
    proc, peer, x, y = connect()
    try:
        d1, d2 = b"first-", b"second"
        s1 = x + 1
        s2 = s1 + len(d1)

        peer.send(s2, y + 1, ACK, d2)  # Arrives early.
        a = peer.recv_matching(is_pure_ack, T)
        check(a is not None, "no ACK for out-of-order packet")
        check(a.ack == s1, f"ACK after early packet {a.ack}, want {s1}")

        peer.send(s1, y + 1, ACK, d1)  # Fills the gap.
        b = peer.recv_matching(is_pure_ack, T)
        check(b is not None, "no ACK after gap filled")
        want = s2 + len(d2)
        check(b.ack == want, f"ACK after gap filled {b.ack}, want {want}")
    finally:
        stop(proc, peer)


TESTS = [
    test_lost_data_retransmitted_until_received,
    test_go_back_n_resends_everything_outstanding,
    test_large_transfer_split_and_intact,
    test_lost_ack_receiver_reacks_duplicate,
    test_lost_ack_covered_by_later_ack,
    test_reordering_acks_only_cover_in_order_data,
]

if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        print(f"Running {test.__name__}()")
        try:
            test()
            print("Test passed")
        except AssertionError as e:
            failed += 1
            print(f"Test Failed: {e}")
    print(f"{len(TESTS) - failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)
