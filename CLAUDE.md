# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Course agent policy (read first)

This is a student repo for CMU 15-441/641 Project 2 ("TCP in the Wild"). The course defines how coding agents may help, and those rules take precedence over normal coding-agent behavior:

- @.agent/AGENT.md: role, workflow, and interaction-history (`history.md`) rules.
- @.agent/P2LEARNINGGOALS.md: the protected learning objectives. Where `AGENT.md` says `goals.md`, it means this file.

In short, the student designs the protocol and writes the pseudocode. You help them understand, implement, test, and debug *their* design. Do not invent protocol logic yourself (handshake/teardown state machines, sliding window, retransmission/RTO, congestion control, and so on). Copies of both files also sit untracked at the repo root; the `.agent/` versions are the tracked ones.

## Environment

All code lives in `project-2_15-441/`. The code has to be built and run inside the Vagrant/Docker containers, because the tests depend on the container hostnames, IPs, and MACs (client `10.0.1.2`, server `10.0.1.1`), plus `sudo`, scapy, and tmux:

```bash
vagrant up --provider=docker
vagrant ssh server        # or: vagrant ssh client
cd /vagrant/project-2_15-441/
```

`Vagrantfile` shapes the link to 100 Mbps with 20 ms delay (`tcset` on `$IFNAME`). Use real AWS instances, not Docker, for the CP2 experiments.

## Commands (run from `project-2_15-441/` inside a container)

- `make`: builds `server`, `client`, and `tests/testing_server` (gcc, `-Wall -Wextra -pedantic -DDEBUG -pthread`; objects go in `build/`).
- `make test`: runs `sudo -E python3 tests/test_cp1.py` and `tests/test_cp1_basic_ack_packets.py`. To run a single file, invoke it the same way. Each test is a plain function called from `__main__`, not pytest.
- `make format`: runs `pre-commit run --all-files` (clang-format Google style, cpplint, cppcheck, black with 79-column lines).
- `make clean`
- Manual run: `./server` in the server container and `./client` in the client container.
- Packet capture: `./utils/capture_packets.sh start|stop|analyze cap.pcap`. View captures in Wireshark using the `utils/tcp.lua` dissector.
- Submission: `./utils/prepare_submission.sh` (run from the repo root after committing). It produces `handin.tar.gz`.

## Architecture

The library is a TCP-like reliable transport built on UDP. Each `cmu_socket_t` has two threads:

- **Application side** (`src/cmu_tcp.c`): `cmu_socket` creates the UDP socket and starts the backend thread. `cmu_write` only appends to `sending_buf` (under `send_lock`). `cmu_read` takes data from `received_buf` (under `recv_lock`) and blocks on `wait_cond` in `NO_FLAG` mode. `cmu_close` sets `dying` (under `death_lock`) and joins the backend.
- **Backend thread** (`src/backend.c`, `begin_backend`): loops until `dying` is set and the send buffer is empty. On each pass it drains `sending_buf` into `single_send`, polls the socket with `check_for_data`, and signals `wait_cond` when received data is available. `handle_message` processes each incoming packet. The starter code is stop-and-wait with no handshake, and its sequence numbers start at 0 (see the `FIXME`s). Most of the protocol work goes here.
- **Packets** (`inc/cmu_packet.h`, `src/cmu_packet.c`): fixed header with course number, ports, seq/ack, hlen/plen, flags (`SYN`/`ACK`/`FIN` masks), advertised window, and an extension field. Use the getters/setters and `create_packet`, which handle byte-order conversion. Use `before`/`after` for sequence comparisons.
- `cmu_socket_t` and `window_t` in `inc/cmu_tcp.h` can be extended. The API declarations marked "DO NOT CHANGE" cannot.

## Files the grader replaces or depends on

- `inc/cmu_packet.h`: do not modify. The analysis tools (`tcp.lua`, `tests/common.py`) depend on its exact header layout.
- `inc/grading.h`: do not modify. The autograder replaces it with other values (`MAX_LEN`, window sizes, `DEFAULT_TIMEOUT`, buffer size), so code must not hard-code assumptions about these values.
- `src/server.c` and `src/client.c`: graders use their own apps, so protocol state or helpers must not live in these files.
- `tests.txt`: the student's written testing strategy. Document any `Vagrantfile` or tooling changes here.
- CP2: the sender must log timestamp, `cwnd`, `ssthresh`, and congestion-control stage each time any of them changes. These logs are used for the cwnd-over-time plots.
