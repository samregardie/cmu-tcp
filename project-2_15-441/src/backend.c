/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// The handshake gives up after this many unanswered transmissions. After
// cmu_close, unACKed data is abandoned after this many timeouts in a row with
// no ACK.
#define MAX_HANDSHAKE_ATTEMPTS 10

// After the first FIN, resend it FIN_RESENDS times, evenly spaced, and stop
// waiting for its ACK FIN_GIVE_UP_MS after the first FIN.
#define FIN_RESENDS 3
#define FIN_GIVE_UP_MS (2 * DEFAULT_TIMEOUT)
#define FIN_RESEND_INTERVAL_MS (FIN_GIVE_UP_MS / (FIN_RESENDS + 1))

// FINAL_WAIT lasts two segment lifetimes. The project has no maximum segment
// lifetime, so one lifetime is taken to be DEFAULT_TIMEOUT.
#define SEGMENT_LIFETIME_MS DEFAULT_TIMEOUT
#define FINAL_WAIT_MS (2 * SEGMENT_LIFETIME_MS)

// How long each backend loop pass waits for a packet. New app data and timer
// expiry are noticed at most this late.
#define BACKEND_POLL_MS 1

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Current time on a monotonic clock, in milliseconds.
 */
static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void lock(pthread_mutex_t *mutex) {
  while (pthread_mutex_lock(mutex) != 0) {
  }
}

static int is_dying(cmu_socket_t *sock) {
  lock(&sock->death_lock);
  int dying = sock->dying;
  pthread_mutex_unlock(&sock->death_lock);
  return dying;
}

static int peer_has_closed(cmu_socket_t *sock) {
  lock(&sock->recv_lock);
  int closed = sock->peer_fin_received;
  pthread_mutex_unlock(&sock->recv_lock);
  return closed;
}

/**
 * Sends one packet (no extension) to the peer.
 */
static void send_packet(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                        uint8_t flags, uint8_t *payload, uint16_t len) {
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + len;
  uint8_t *pkt = create_packet(sock->my_port, ntohs(sock->conn.sin_port), seq,
                               ack, hlen, plen, flags, 1, 0, NULL, payload, len);
  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         sizeof(sock->conn));
  free(pkt);
}

// Handshake packets. The SYN uses one sequence number in each direction.
static void send_syn(cmu_socket_t *sock) {
  send_packet(sock, sock->my_isn, 0, SYN_FLAG_MASK, NULL, 0);
}

static void send_syn_ack(cmu_socket_t *sock) {
  send_packet(sock, sock->my_isn, sock->peer_isn + 1,
              SYN_FLAG_MASK | ACK_FLAG_MASK, NULL, 0);
}

static void send_handshake_ack(cmu_socket_t *sock) {
  send_packet(sock, sock->my_isn + 1, sock->peer_isn + 1, ACK_FLAG_MASK, NULL,
              0);
}

// Connected packets all carry our cumulative ACK (next byte expected).
static void send_ack(cmu_socket_t *sock) {
  send_packet(sock, sock->window.able_to_send, sock->window.next_seq_expected,
              ACK_FLAG_MASK, NULL, 0);
}

static void send_data(cmu_socket_t *sock, segment_t *seg) {
  send_packet(sock, seg->seq, sock->window.next_seq_expected, ACK_FLAG_MASK,
              seg->data, seg->len);
}

static void send_fin(cmu_socket_t *sock) {
  send_packet(sock, sock->window.fin_seq, sock->window.next_seq_expected,
              FIN_FLAG_MASK | ACK_FLAG_MASK, NULL, 0);
}

static segment_t *segment_new(uint32_t seq, const uint8_t *data,
                              uint16_t len) {
  segment_t *seg = malloc(sizeof(segment_t));
  seg->seq = seq;
  seg->len = len;
  seg->data = malloc(len);
  memcpy(seg->data, data, len);
  seg->next = NULL;
  return seg;
}

static void segment_free(segment_t *seg) {
  free(seg->data);
  free(seg);
}

static void free_segments(segment_t *seg) {
  while (seg != NULL) {
    segment_t *next = seg->next;
    segment_free(seg);
    seg = next;
  }
}

/* ------------------------------------------------------------------------ */
/* Handshake                                                                */
/* ------------------------------------------------------------------------ */

/**
 * Handles a packet received before the connection is established.
 *
 * @param from Address the packet came from. Only an accepted SYN makes it the
 *             peer address (`sock->conn`).
 */
static void handle_handshake_message(cmu_socket_t *sock, uint8_t *pkt,
                                     const struct sockaddr_in *from) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);
  uint32_t seq = get_seq(hdr);
  uint32_t ack = get_ack(hdr);

  switch (sock->state) {
    case STATE_IDLE:
      // Server: on SYN, the sender becomes the peer; reply SYN-ACK.
      if (flags == SYN_FLAG_MASK) {
        sock->conn = *from;
        sock->peer_isn = seq;
        send_syn_ack(sock);
        sock->state = STATE_WAITING_FOR_ACK;
      }
      break;

    case STATE_WAITING_FOR_ACK:
      if (flags & ACK_FLAG_MASK) {
        int pure_ack = flags == ACK_FLAG_MASK && get_payload_len(pkt) == 0;
        // A pure ACK must match exactly; any other packet with ACK set only
        // needs seq and ack past the ISNs (its payload is dropped).
        int valid = pure_ack ? seq == sock->peer_isn + 1 &&
                                   ack == sock->my_isn + 1
                             : after(seq, sock->peer_isn) &&
                                   after(ack, sock->my_isn);
        if (valid) {
          sock->state = STATE_CONNECTED;
        }
      } else if (flags == SYN_FLAG_MASK && seq == sock->peer_isn) {
        send_syn_ack(sock);  // Repeated SYN: same SYN-ACK, same ISN.
      }
      break;

    case STATE_SYN_SENT:
      // Client: on SYN-ACK acknowledging our SYN, send the final ACK.
      if (flags == (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
          ack == sock->my_isn + 1) {
        sock->peer_isn = seq;
        send_handshake_ack(sock);
        sock->state = STATE_CONNECTED;
      }
      break;

    default:
      break;
  }
  // Anything not matched above is ignored.
}

/* ------------------------------------------------------------------------ */
/* Sender                                                                   */
/* ------------------------------------------------------------------------ */

static void timer_restart(cmu_socket_t *sock) {
  sock->window.timer_running = 1;
  sock->window.timer_deadline = now_ms() + DEFAULT_TIMEOUT;
}

/**
 * Moves everything the application has written from sending_buf into the
 * backend's `unsent` queue.
 */
static void take_app_data(cmu_socket_t *sock) {
  window_t *w = &sock->window;

  lock(&sock->send_lock);
  if (sock->sending_len > 0) {
    int remaining = w->unsent_len - w->unsent_off;
    uint8_t *buf = malloc(remaining + sock->sending_len);
    if (remaining > 0) {
      memcpy(buf, w->unsent + w->unsent_off, remaining);
    }
    memcpy(buf + remaining, sock->sending_buf, sock->sending_len);
    free(w->unsent);
    w->unsent = buf;
    w->unsent_off = 0;
    w->unsent_len = remaining + sock->sending_len;

    free(sock->sending_buf);
    sock->sending_buf = NULL;
    sock->sending_len = 0;
  }
  pthread_mutex_unlock(&sock->send_lock);
}

/**
 * Sends new packets from `unsent` while they fit in the window.
 */
static void send_ready(cmu_socket_t *sock) {
  window_t *w = &sock->window;

  while (w->unsent_off < w->unsent_len) {
    uint16_t len =
        MIN((uint32_t)(w->unsent_len - w->unsent_off), (uint32_t)MSS);
    uint32_t in_flight_bytes = w->able_to_send - w->oldest_pending;
    if (in_flight_bytes + len > (uint32_t)CP1_WINDOW_SIZE) {
      break;  // Wait: this packet would overfill the window.
    }

    segment_t *seg = segment_new(w->able_to_send, w->unsent + w->unsent_off,
                                 len);
    if (w->in_flight_tail != NULL) {
      w->in_flight_tail->next = seg;
    } else {
      w->in_flight = seg;
    }
    w->in_flight_tail = seg;

    send_data(sock, seg);
    w->able_to_send += len;
    w->unsent_off += len;
    timer_restart(sock);  // Start/restart on every send.
  }

  if (w->unsent_off == w->unsent_len) {
    free(w->unsent);
    w->unsent = NULL;
    w->unsent_off = 0;
    w->unsent_len = 0;
  }
}

/**
 * Sender side of an incoming packet with the ACK flag set.
 */
static void handle_ack(cmu_socket_t *sock, uint32_t ack) {
  window_t *w = &sock->window;

  w->timeouts_without_ack = 0;  // Any ACK shows the peer is still there.

  // Ignore ACKs with no new info and ACKs beyond anything we've sent.
  if (!after(ack, w->oldest_pending) || after(ack, w->able_to_send)) {
    return;
  }
  w->oldest_pending = ack;

  // Free packets the ACK fully covers. A packet the ACK lands inside is kept.
  while (w->in_flight != NULL &&
         !after(w->in_flight->seq + w->in_flight->len, ack)) {
    segment_t *done = w->in_flight;
    w->in_flight = done->next;
    segment_free(done);
  }
  if (w->in_flight == NULL) {
    w->in_flight_tail = NULL;
  }

  // New ACK: restart the timer, or stop it if nothing is outstanding.
  if (w->oldest_pending == w->able_to_send) {
    w->timer_running = 0;
  } else {
    timer_restart(sock);
  }
}

/**
 * On timeout, Go-Back-N: resend every packet from oldest_pending onward.
 */
static void check_timer(cmu_socket_t *sock) {
  window_t *w = &sock->window;
  if (!w->timer_running || now_ms() < w->timer_deadline) {
    return;
  }
  for (segment_t *seg = w->in_flight; seg != NULL; seg = seg->next) {
    send_data(sock, seg);
  }
  w->timeouts_without_ack++;
  timer_restart(sock);
}

/* ------------------------------------------------------------------------ */
/* Receiver (caller holds recv_lock)                                        */
/* ------------------------------------------------------------------------ */

/**
 * Appends bytes to received_buf for the application.
 */
static void deliver(cmu_socket_t *sock, uint8_t *data, uint32_t len) {
  sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
  memcpy(sock->received_buf + sock->received_len, data, len);
  sock->received_len += len;
}

/**
 * Delivers the part of [seq, seq + len) past next_seq_expected, which must
 * not leave a gap (seq <= next_seq_expected).
 */
static void deliver_new_bytes(cmu_socket_t *sock, uint32_t seq,
                              uint8_t *data, uint16_t len) {
  window_t *w = &sock->window;
  uint32_t end = seq + len;
  if (after(end, w->next_seq_expected)) {
    uint32_t skip = w->next_seq_expected - seq;
    deliver(sock, data + skip, len - skip);
    w->next_seq_expected = end;
  }
}

/**
 * Receiver side of an incoming packet with a payload. Always answers with an
 * ACK for the in-order data received so far.
 */
static void handle_data(cmu_socket_t *sock, uint32_t seq, uint8_t *payload,
                        uint16_t len) {
  window_t *w = &sock->window;

  if (!after(seq, w->next_seq_expected)) {
    // In order (a full duplicate delivers nothing and is just re-ACKed).
    deliver_new_bytes(sock, seq, payload, len);

    // Kept out-of-order data that is now in order gets delivered too.
    while (w->out_of_order != NULL &&
           !after(w->out_of_order->seq, w->next_seq_expected)) {
      segment_t *seg = w->out_of_order;
      w->out_of_order = seg->next;
      deliver_new_bytes(sock, seg->seq, seg->data, seg->len);
      segment_free(seg);
    }
  } else {
    // Out of order: keep it, sorted by seq, unless we already hold it.
    segment_t **pos = &w->out_of_order;
    while (*pos != NULL && before((*pos)->seq, seq)) {
      pos = &(*pos)->next;
    }
    if (*pos == NULL || (*pos)->seq != seq) {
      segment_t *seg = segment_new(seq, payload, len);
      seg->next = *pos;
      *pos = seg;
    }
  }

  send_ack(sock);
}

/**
 * Receiver side of a FIN. If everything before it has arrived, the peer is
 * closed (the FIN uses one sequence number). Always ACKs.
 */
static void handle_fin(cmu_socket_t *sock, uint32_t seq) {
  window_t *w = &sock->window;
  if (!sock->peer_fin_received && seq == w->next_seq_expected) {
    w->next_seq_expected = seq + 1;
    sock->peer_fin_received = 1;
  }
  send_ack(sock);
}

/* ------------------------------------------------------------------------ */
/* Teardown                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * Sends our FIN. It takes the next sequence number, so its ACK is
 * fin_seq + 1. Any data not yet sent is abandoned.
 */
static void start_close(cmu_socket_t *sock, int peer_closed, int64_t now) {
  window_t *w = &sock->window;

  w->peer_closed_first = peer_closed;
  w->fin_seq = w->able_to_send;
  w->able_to_send += 1;
  w->fin_resends = 0;
  w->fin_next_resend = now + FIN_RESEND_INTERVAL_MS;
  w->fin_give_up = now + FIN_GIVE_UP_MS;
  send_fin(sock);
  sock->state = STATE_WAITING_FOR_FIN_ACK;
}

static void enter_final_wait(cmu_socket_t *sock, int64_t now) {
  sock->state = STATE_FINAL_WAIT;
  sock->window.final_wait_end = now + FINAL_WAIT_MS;
}

/**
 * Advances the teardown state machine (see cmu_conn_state_t).
 *
 * @return 1 when the backend should exit, 0 otherwise.
 */
static int teardown_step(cmu_socket_t *sock, int dying, int peer_closed) {
  window_t *w = &sock->window;
  int64_t now = now_ms();

  switch (sock->state) {
    case STATE_CONNECTED: {
      int all_acked =
          w->unsent_len == 0 && w->oldest_pending == w->able_to_send;
      int gave_up = w->timeouts_without_ack >= MAX_HANDSHAKE_ATTEMPTS;
      if (dying && (all_acked || gave_up)) {
        start_close(sock, peer_closed, now);
      }
      return 0;
    }

    case STATE_WAITING_FOR_FIN_ACK: {
      int fin_acked = !before(w->oldest_pending, w->fin_seq + 1);
      if (fin_acked || now >= w->fin_give_up) {
        if (w->peer_closed_first) {
          return 1;  // Both sides done; we closed second.
        } else if (peer_closed) {
          enter_final_wait(sock, now);  // Peer's FIN came after ours.
        } else {
          sock->state = STATE_WAITING_FOR_PEER_FIN;
        }
      } else if (w->fin_resends < FIN_RESENDS && now >= w->fin_next_resend) {
        send_fin(sock);
        w->fin_resends++;
        w->fin_next_resend = now + FIN_RESEND_INTERVAL_MS;
      }
      return 0;
    }

    case STATE_WAITING_FOR_PEER_FIN:
      // Keep receiving and ACKing the peer's data until its FIN arrives.
      if (peer_closed) {
        enter_final_wait(sock, now);
      }
      return 0;

    case STATE_FINAL_WAIT:
      // Retransmitted FINs are re-ACKed by handle_fin().
      return now >= w->final_wait_end;

    default:
      return 0;
  }
}

/* ------------------------------------------------------------------------ */
/* Packet input                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Dispatches a received packet. Caller holds recv_lock.
 */
static void handle_message(cmu_socket_t *sock, uint8_t *pkt,
                           const struct sockaddr_in *from) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  if (sock->state == STATE_IDLE || sock->state == STATE_SYN_SENT ||
      sock->state == STATE_WAITING_FOR_ACK) {
    handle_handshake_message(sock, pkt, from);
    return;
  }

  // Client: a SYN-ACK after connecting means our final ACK may have been
  // lost, so ACK it again.
  if (sock->type == TCP_INITIATOR &&
      flags == (SYN_FLAG_MASK | ACK_FLAG_MASK)) {
    send_handshake_ack(sock);
    return;
  }

  // One packet can carry an ACK, data, and a FIN: handle them in that order.
  if (flags & ACK_FLAG_MASK) {
    handle_ack(sock, get_ack(hdr));
  }
  if (get_payload_len(pkt) > 0) {
    handle_data(sock, get_seq(hdr), get_payload(pkt), get_payload_len(pkt));
  }
  if (flags & FIN_FLAG_MASK) {
    handle_fin(sock, get_seq(hdr));
  }
}

/**
 * Reads one packet, if any, and handles it. It first peeks at the header to
 * learn the packet length, then reads the whole packet.
 *
 * @param flags NO_FLAG blocks until a packet arrives; NO_WAIT returns
 *              immediately if there is none.
 */
static void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  struct sockaddr_in from;
  socklen_t from_len = sizeof(from);
  int peek_flags = MSG_PEEK | (flags == NO_WAIT ? MSG_DONTWAIT : 0);

  lock(&sock->recv_lock);
  ssize_t len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                         peek_flags, (struct sockaddr *)&from, &from_len);
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    uint32_t plen = get_plen(&hdr);
    uint32_t buf_size = 0;
    uint8_t *pkt = malloc(plen);
    while (buf_size < plen) {
      buf_size += recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                           (struct sockaddr *)&from, &from_len);
    }
    handle_message(sock, pkt, &from);
    free(pkt);
  }
  pthread_mutex_unlock(&sock->recv_lock);
}

/**
 * Waits up to `timeout_ms` for a packet (without holding recv_lock), then
 * handles it if one arrived.
 */
static void wait_for_packet(cmu_socket_t *sock, int timeout_ms) {
  struct pollfd pfd = {.fd = sock->socket, .events = POLLIN};
  if (poll(&pfd, 1, timeout_ms) > 0) {
    check_for_data(sock, NO_WAIT);
  }
}

/* ------------------------------------------------------------------------ */
/* Entry points                                                             */
/* ------------------------------------------------------------------------ */

int cmu_handshake(cmu_socket_t *sock) {
  int attempts = 0;
  int64_t deadline = 0;

  if (sock->type == TCP_INITIATOR) {
    send_syn(sock);
    sock->state = STATE_SYN_SENT;
    attempts = 1;
    deadline = now_ms() + DEFAULT_TIMEOUT;
  } else {
    sock->state = STATE_IDLE;
  }

  while (sock->state != STATE_CONNECTED) {
    if (sock->state == STATE_IDLE) {
      // Server: wait for a SYN with no timeout.
      check_for_data(sock, NO_FLAG);
      if (sock->state == STATE_WAITING_FOR_ACK) {
        attempts = 1;  // The SYN-ACK was just sent; start its timer.
        deadline = now_ms() + DEFAULT_TIMEOUT;
      }
      continue;
    }

    // Wait only for the time left until the deadline, so packets that get
    // ignored don't push the timeout back.
    int64_t remaining = deadline - now_ms();
    if (remaining > 0) {
      wait_for_packet(sock, (int)remaining);
      continue;
    }

    // Timed out: give up, or retransmit with the same ISN.
    if (attempts >= MAX_HANDSHAKE_ATTEMPTS) {
      if (sock->state == STATE_SYN_SENT) {
        return EXIT_ERROR;
      }
      sock->state = STATE_IDLE;  // Server: abandon this client.
      sock->peer_isn = 0;
      continue;
    }
    if (sock->state == STATE_SYN_SENT) {
      send_syn(sock);
    } else {
      send_syn_ack(sock);
    }
    attempts++;
    deadline = now_ms() + DEFAULT_TIMEOUT;
  }

  // Data starts at ISN + 1 in each direction.
  sock->window.oldest_pending = sock->my_isn + 1;
  sock->window.able_to_send = sock->my_isn + 1;
  sock->window.next_seq_expected = sock->peer_isn + 1;
  return EXIT_SUCCESS;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  window_t *w = &sock->window;

  while (1) {
    // Read `dying` before taking app data, so anything written before
    // cmu_close is taken before the FIN can be sent.
    int dying = is_dying(sock);
    take_app_data(sock);
    if (teardown_step(sock, dying, peer_has_closed(sock))) {
      break;
    }

    wait_for_packet(sock, BACKEND_POLL_MS);

    // No new data after our FIN. Receiving the peer's FIN doesn't stop us.
    if (sock->state == STATE_CONNECTED) {
      send_ready(sock);
    }
    check_timer(sock);

    // Wake a blocked cmu_read if there is data or the peer has closed.
    lock(&sock->recv_lock);
    int wake = sock->received_len > 0 || sock->peer_fin_received;
    pthread_mutex_unlock(&sock->recv_lock);
    if (wake) {
      pthread_cond_signal(&sock->wait_cond);
    }
  }

  free_segments(w->in_flight);
  free_segments(w->out_of_order);
  free(w->unsent);

  pthread_exit(NULL);
  return NULL;
}
