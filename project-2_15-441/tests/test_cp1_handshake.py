#!/usr/bin/env python3
"""Handshake tests.

Each test runs a real binary (tests/testing_server or ./client) against a
fake peer: a plain UDP socket on localhost. A packet is "lost" by having the
fake peer not send it, or ignore it when it arrives. Runs on either VM and
does not need sudo:

    python3 tests/test_cp1_handshake.py
"""

import os
import re
import socket
import struct
import subprocess
import sys
import time
from collections import namedtuple

CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Matches cmu_tcp_header_t in inc/cmu_packet.h (25 bytes, network order).
HDR = struct.Struct("!IHHIIHHBHH")
IDENTIFIER = 15441
FIN, ACK, SYN = 0x2, 0x4, 0x8

# Must match MAX_HANDSHAKE_ATTEMPTS in src/backend.c.
MAX_ATTEMPTS = 10

Pkt = namedtuple("Pkt", "seq ack flags payload time")


def read_default_timeout():
    with open(os.path.join(CODE_DIR, "inc", "grading.h")) as f:
        m = re.search(r"#define\s+DEFAULT_TIMEOUT\s+(\d+)", f.read())
    return int(m.group(1)) / 1000.0


T = read_default_timeout()


class FakePeer:
    """A UDP socket that speaks the CMU-TCP header format."""

    def __init__(self, remote_port=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.remote = ("127.0.0.1", remote_port) if remote_port else None

    def send(self, seq, ack, flags, payload=b""):
        plen = HDR.size + len(payload)
        hdr = HDR.pack(
            IDENTIFIER, self.port, self.remote[1], seq, ack,
            HDR.size, plen, flags, 1, 0,
        )
        self.sock.sendto(hdr + payload, self.remote)

    def recv(self, timeout):
        """Returns the next packet within `timeout` seconds, or None."""
        self.sock.settimeout(max(timeout, 0.001))
        try:
            data, addr = self.sock.recvfrom(65535)
        except socket.timeout:
            return None
        self.remote = addr
        f = HDR.unpack_from(data)
        return Pkt(f[3], f[4], f[7], data[f[5]:], time.monotonic())

    def recv_matching(self, pred, timeout):
        """Returns the first packet satisfying `pred` within `timeout`."""
        deadline = time.monotonic() + timeout
        while True:
            p = self.recv(deadline - time.monotonic())
            if p is None or pred(p):
                return p

    def close(self):
        self.sock.close()


def is_synack(p):
    return p.flags == SYN | ACK


def is_syn(p):
    return p.flags == SYN


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start(binary, port):
    env = dict(os.environ, server15441="127.0.0.1", serverport15441=str(port))
    return subprocess.Popen(
        [os.path.join(CODE_DIR, binary)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def start_server():
    """Starts testing_server; returns (process, fake client)."""
    port = free_port()
    proc = start("tests/testing_server", port)
    time.sleep(0.5)  # Let it bind before we send anything.
    return proc, FakePeer(remote_port=port)


def start_client():
    """Starts ./client against a fake server; returns (process, fake)."""
    peer = FakePeer()
    return start("client", peer.port), peer


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def check_interval(earlier, later, what):
    gap = later.time - earlier.time
    check(
        0.8 * T <= gap <= 1.5 * T,
        f"{what} came {gap:.2f}s apart; expected about {T:.2f}s",
    )


# --------------------------------------------------------------------------
# Server side (fake client talks to testing_server)
# --------------------------------------------------------------------------


def test_server_all_succeed():
    """All messages arrive: server ends up connected."""
    proc, peer = start_server()
    try:
        x = 1000
        peer.send(x, 0, SYN)
        synack = peer.recv(T)
        check(synack is not None, "no reply to SYN")
        check(is_synack(synack), f"reply flags {synack.flags:#x}, want SYN|ACK")
        check(synack.ack == x + 1, f"SYN-ACK ack {synack.ack}, want {x + 1}")
        y = synack.seq

        peer.send(x + 1, y + 1, ACK)
        extra = peer.recv(1.5 * T)
        check(extra is None, f"server sent {extra} after final ACK")

        # Connected check: the current (starter) data path ACKs a flags=0
        # data packet. Update this when your data path changes.
        peer.send(x + 1, y + 1, 0, b"hi")
        reply = peer.recv_matching(lambda p: p.flags == ACK, T)
        check(reply is not None, "no ACK for data; server not connected?")
        check(reply.ack == x + 1 + 2, f"data ACK {reply.ack}, want {x + 3}")
    finally:
        proc.kill()
        proc.wait()
        peer.close()


def test_server_lost_synack():
    """SYN-ACK lost: server retransmits it; a repeated SYN gets it again."""
    proc, peer = start_server()
    try:
        x = 1000
        peer.send(x, 0, SYN)
        first = peer.recv(T)
        check(first is not None and is_synack(first), "no SYN-ACK")
        # Pretend `first` was lost.

        again = peer.recv_matching(is_synack, 1.5 * T)
        check(again is not None, "server did not retransmit SYN-ACK")
        check_interval(first, again, "SYN-ACK retransmissions")
        check(
            (again.seq, again.ack) == (first.seq, first.ack),
            f"retransmit seq/ack {again.seq}/{again.ack}, "
            f"want {first.seq}/{first.ack}",
        )

        # Client also retransmits its SYN: expect an immediate SYN-ACK.
        peer.send(x, 0, SYN)
        reply = peer.recv_matching(is_synack, 0.5 * T)
        check(reply is not None, "no SYN-ACK for repeated SYN")
        check(
            (reply.seq, reply.ack) == (first.seq, first.ack),
            f"reply seq/ack {reply.seq}/{reply.ack}, "
            f"want {first.seq}/{first.ack}",
        )
    finally:
        proc.kill()
        proc.wait()
        peer.close()


def test_server_lost_final_ack_nothing_else():
    """Final ACK lost, nothing else sent: server gives up, back to IDLE."""
    proc, peer = start_server()
    try:
        x = 1000
        peer.send(x, 0, SYN)
        synacks = []
        while True:
            p = peer.recv_matching(is_synack, 1.5 * T)
            if p is None:
                break
            synacks.append(p)
        check(
            len(synacks) == MAX_ATTEMPTS,
            f"got {len(synacks)} SYN-ACKs, want {MAX_ATTEMPTS}",
        )
        check(
            len({p.seq for p in synacks}) == 1,
            "SYN-ACK retransmissions used different ISNs",
        )

        # Back in IDLE: a new SYN starts a new handshake.
        x2 = 5000
        peer.send(x2, 0, SYN)
        reply = peer.recv_matching(is_synack, T)
        check(reply is not None, "no SYN-ACK for new SYN; server not IDLE?")
        check(reply.ack == x2 + 1, f"SYN-ACK ack {reply.ack}, want {x2 + 1}")
    finally:
        proc.kill()
        proc.wait()
        peer.close()


def test_server_lost_final_ack_then_data():
    """Final ACK lost, then a data packet with ACK set: server connects."""
    proc, peer = start_server()
    try:
        x = 1000
        peer.send(x, 0, SYN)
        synack = peer.recv(T)
        check(synack is not None and is_synack(synack), "no SYN-ACK")
        y = synack.seq
        # Final ACK "lost": skip it and send data with ACK set instead.
        peer.send(x + 1, y + 1, ACK, b"hi")

        extra = peer.recv_matching(is_synack, 1.5 * T)
        check(extra is None, "server still retransmitting SYN-ACK")
    finally:
        proc.kill()
        proc.wait()
        peer.close()


# --------------------------------------------------------------------------
# Client side (./client talks to a fake server)
# --------------------------------------------------------------------------


def test_client_all_succeed():
    """All messages arrive: client ACKs and starts sending data at ISN+1."""
    proc, peer = start_client()
    try:
        syn = peer.recv(2 * T)
        check(syn is not None and is_syn(syn), "client did not send a SYN")
        x, y = syn.seq, 5000

        peer.send(y, x + 1, SYN | ACK)
        ack = peer.recv_matching(lambda p: p.flags == ACK and not p.payload, T)
        check(ack is not None, "client did not ACK the SYN-ACK")
        check(
            (ack.seq, ack.ack) == (x + 1, y + 1),
            f"final ACK seq/ack {ack.seq}/{ack.ack}, want {x + 1}/{y + 1}",
        )

        data = peer.recv_matching(lambda p: p.payload, T)
        check(data is not None, "client sent no data; not connected?")
        check(data.seq == x + 1, f"first data seq {data.seq}, want {x + 1}")
    finally:
        proc.kill()
        proc.wait()
        peer.close()


def test_client_lost_syn():
    """First two SYNs lost: client retransmits until it gets a SYN-ACK."""
    proc, peer = start_client()
    try:
        first = peer.recv(2 * T)
        check(first is not None and is_syn(first), "client sent no SYN")
        prev = first
        for _ in range(2):  # Drop `prev`, wait for the retransmission.
            p = peer.recv_matching(is_syn, 1.5 * T)
            check(p is not None, "client did not retransmit SYN")
            check_interval(prev, p, "SYN retransmissions")
            check(p.seq == first.seq, f"SYN seq {p.seq}, want {first.seq}")
            prev = p

        x, y = first.seq, 5000
        peer.send(y, x + 1, SYN | ACK)
        ack = peer.recv_matching(lambda p: p.flags == ACK and not p.payload, T)
        check(ack is not None, "client did not ACK the SYN-ACK")

        extra = peer.recv_matching(is_syn, 1.5 * T)
        check(extra is None, "client kept sending SYNs after connecting")
    finally:
        proc.kill()
        proc.wait()
        peer.close()


TESTS = [
    test_server_all_succeed,
    test_server_lost_synack,
    test_server_lost_final_ack_nothing_else,
    test_server_lost_final_ack_then_data,
    test_client_all_succeed,
    test_client_lost_syn,
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
