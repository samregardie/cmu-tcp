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
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
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

// Handshake gives up after this many unanswered transmissions.
#define MAX_HANDSHAKE_ATTEMPTS 10

// After the first FIN, resend it this many times, evenly spaced, and exit
// 2 x DEFAULT_TIMEOUT after the first FIN if it is never ACKed. Giving up on
// unACKed data after cmu_close reuses MAX_HANDSHAKE_ATTEMPTS.
#define FIN_RESENDS 3
#define FIN_GIVE_UP_MS (2 * DEFAULT_TIMEOUT)

// FINAL_WAIT lasts two segment lifetimes. The project has no maximum segment
// lifetime, so one lifetime is taken to be DEFAULT_TIMEOUT.
#define SEGMENT_LIFETIME_MS DEFAULT_TIMEOUT
#define FINAL_WAIT_MS (2 * SEGMENT_LIFETIME_MS)

// How long each backend loop pass waits for a packet. New app data and timer
// expiry are noticed at most this late.
#define BACKEND_POLL_MS 1

/**
 * Current time on a monotonic clock, in milliseconds.
 */
static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * Sends a packet with no payload and no extension.
 *
 * @param sock The socket to send on.
 * @param seq Sequence number to put in the header.
 * @param ack Acknowledgement number to put in the header.
 * @param flags Header flags (e.g. `SYN_FLAG_MASK | ACK_FLAG_MASK`).
 */
static void send_header_only(cmu_socket_t *sock, uint32_t seq, uint32_t ack,
                             uint8_t flags) {
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint8_t *pkt =
      create_packet(sock->my_port, ntohs(sock->conn.sin_port), seq, ack, hlen,
                    hlen, flags, 1, 0, NULL, NULL, 0);
  sendto(sock->socket, pkt, hlen, 0, (struct sockaddr *)&(sock->conn),
         sizeof(sock->conn));
  free(pkt);
}

/**
 * Handles a packet received before the connection is established.
 *
 * @param sock The socket that received the packet.
 * @param pkt The packet data received by the socket.
 * @param from Address the packet came from.
 */
static void handle_handshake_message(cmu_socket_t *sock, uint8_t *pkt,
                                     const struct sockaddr_in *from) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  switch (sock->state) {
    case STATE_IDLE:
      // Server: on SYN, send SYN-ACK (seq = y, ack = client ISN + 1).
      if (flags == SYN_FLAG_MASK) {
        // Accepted SYN: this sender becomes the peer.
        sock->conn = *from;
        sock->peer_isn = get_seq(hdr);
        send_header_only(sock, sock->my_isn, sock->peer_isn + 1,
                         SYN_FLAG_MASK | ACK_FLAG_MASK);
        sock->state = STATE_WAITING_FOR_ACK;
      }
      // Any non-SYN packet is ignored.
      break;

    case STATE_WAITING_FOR_ACK:
      if (flags & ACK_FLAG_MASK) {
        int pure_ack = flags == ACK_FLAG_MASK && get_payload_len(pkt) == 0;
        if (pure_ack) {
          // Pure ACK: seq = client ISN + 1, ack = y + 1 exactly.
          if (get_seq(hdr) == sock->peer_isn + 1 &&
              get_ack(hdr) == sock->my_isn + 1) {
            sock->state = STATE_CONNECTED;
          }
        } else if (after(get_seq(hdr), sock->peer_isn) &&
                   after(get_ack(hdr), sock->my_isn)) {
          // Any other packet with ACK set: seq and ack only need to be past
          // the ISNs. Its payload is dropped so data handling stays in one
          // place (handle_message once CONNECTED).
          sock->state = STATE_CONNECTED;
        }
      } else if (flags == SYN_FLAG_MASK && get_seq(hdr) == sock->peer_isn) {
        // Repeated SYN (same client ISN): resend the same SYN-ACK, same ISN.
        send_header_only(sock, sock->my_isn, sock->peer_isn + 1,
                         SYN_FLAG_MASK | ACK_FLAG_MASK);
      }
      // Anything else is ignored.
      break;

    case STATE_SYN_SENT:
      // Client: on SYN-ACK with ack = my ISN + 1, send final ACK
      // (seq = my ISN + 1, ack = server ISN + 1), connected.
      if (flags == (SYN_FLAG_MASK | ACK_FLAG_MASK) &&
          get_ack(hdr) == sock->my_isn + 1) {
        sock->peer_isn = get_seq(hdr);
        send_header_only(sock, sock->my_isn + 1, sock->peer_isn + 1,
                         ACK_FLAG_MASK);
        sock->state = STATE_CONNECTED;
      }
      // Anything else (including a SYN-ACK with the wrong ack) is ignored.
      break;

    default:
      break;
  }
}

/**
 * Sends a data packet. Every data packet carries the ACK flag and our current
 * cumulative ACK.
 */
static void send_data_packet(cmu_socket_t *sock, uint32_t seq, uint8_t *data,
                             uint16_t len) {
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + len;
  uint8_t *pkt = create_packet(
      sock->my_port, ntohs(sock->conn.sin_port), seq,
      sock->window.next_seq_expected, hlen, plen, ACK_FLAG_MASK, 1, 0, NULL,
      data, len);
  sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn),
         sizeof(sock->conn));
  free(pkt);
}

static void timer_restart(cmu_socket_t *sock) {
  sock->window.timer_running = 1;
  sock->window.timer_deadline = now_ms() + DEFAULT_TIMEOUT;
}

static void free_segments(segment_t *seg) {
  while (seg != NULL) {
    segment_t *next = seg->next;
    free(seg->data);
    free(seg);
    seg = next;
  }
}

/**
 * Sender side of an incoming packet with the ACK flag set.
 */
static void handle_ack(cmu_socket_t *sock, uint32_t ack) {
  window_t *w = &sock->window;

  // Any ACK shows the peer is still there.
  w->timeouts_without_ack = 0;

  // Ignore ACKs at or below oldest_pending (no new info) and ACKs beyond
  // anything we've sent.
  if (!after(ack, w->oldest_pending) || after(ack, w->able_to_send)) {
    return;
  }
  w->oldest_pending = ack;

  // Free packets the ACK fully covers. A packet the ACK lands inside is kept.
  while (w->in_flight != NULL &&
         !after(w->in_flight->seq + w->in_flight->len, ack)) {
    segment_t *done = w->in_flight;
    w->in_flight = done->next;
    free(done->data);
    free(done);
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
 * Appends bytes to received_buf for the application. Caller holds recv_lock.
 */
static void deliver(cmu_socket_t *sock, uint8_t *data, uint32_t len) {
  sock->received_buf = realloc(sock->received_buf, sock->received_len + len);
  memcpy(sock->received_buf + sock->received_len, data, len);
  sock->received_len += len;
}

/**
 * Receiver side of an incoming packet with a payload. Always answers with an
 * ACK for the in-order data received so far. Caller holds recv_lock.
 */
static void handle_data(cmu_socket_t *sock, uint32_t seq, uint8_t *payload,
                        uint16_t len) {
  window_t *w = &sock->window;
  uint32_t end = seq + len;

  if (!after(end, w->next_seq_expected)) {
    // Duplicate: everything in it was already received. Just re-ACK.
  } else if (!after(seq, w->next_seq_expected)) {
    // In order (skipping any bytes we already have).
    uint32_t skip = w->next_seq_expected - seq;
    deliver(sock, payload + skip, len - skip);
    w->next_seq_expected = end;

    // Kept out-of-order data that is now in order gets delivered too.
    while (w->out_of_order != NULL &&
           !after(w->out_of_order->seq, w->next_seq_expected)) {
      segment_t *seg = w->out_of_order;
      w->out_of_order = seg->next;
      uint32_t seg_end = seg->seq + seg->len;
      if (after(seg_end, w->next_seq_expected)) {
        skip = w->next_seq_expected - seg->seq;
        deliver(sock, seg->data + skip, seg->len - skip);
        w->next_seq_expected = seg_end;
      }
      free(seg->data);
      free(seg);
    }
  } else {
    // Out of order: keep it, sorted by seq, unless we already hold it.
    segment_t **pos = &w->out_of_order;
    while (*pos != NULL && before((*pos)->seq, seq)) {
      pos = &(*pos)->next;
    }
    if (*pos == NULL || (*pos)->seq != seq) {
      segment_t *seg = malloc(sizeof(segment_t));
      seg->seq = seq;
      seg->len = len;
      seg->data = malloc(len);
      memcpy(seg->data, payload, len);
      seg->next = *pos;
      *pos = seg;
    }
  }

  send_header_only(sock, w->able_to_send, w->next_seq_expected,
                   ACK_FLAG_MASK);
}

/**
 * Sends new packets from `unsent` while they fit in the window.
 */
static void send_ready(cmu_socket_t *sock) {
  window_t *w = &sock->window;

  while (w->unsent_off < w->unsent_len) {
    uint16_t len = MIN((uint32_t)(w->unsent_len - w->unsent_off),
                       (uint32_t)MSS);
    uint32_t in_flight_bytes = w->able_to_send - w->oldest_pending;
    // Wait if this packet would overfill the window.
    if (in_flight_bytes + len > (uint32_t)CP1_WINDOW_SIZE) {
      break;
    }

    segment_t *seg = malloc(sizeof(segment_t));
    seg->seq = w->able_to_send;
    seg->len = len;
    seg->data = malloc(len);
    memcpy(seg->data, w->unsent + w->unsent_off, len);
    seg->next = NULL;
    if (w->in_flight_tail != NULL) {
      w->in_flight_tail->next = seg;
    } else {
      w->in_flight = seg;
    }
    w->in_flight_tail = seg;

    send_data_packet(sock, seg->seq, seg->data, seg->len);
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
 * On timeout, Go-Back-N: resend every packet from oldest_pending onward.
 */
static void check_timer(cmu_socket_t *sock) {
  window_t *w = &sock->window;
  if (!w->timer_running || now_ms() < w->timer_deadline) {
    return;
  }
  for (segment_t *seg = w->in_flight; seg != NULL; seg = seg->next) {
    send_data_packet(sock, seg->seq, seg->data, seg->len);
  }
  w->timeouts_without_ack++;
  timer_restart(sock);
}

/**
 * Sends our FIN (FIN|ACK, carrying our cumulative ACK).
 */
static void send_fin(cmu_socket_t *sock) {
  send_header_only(sock, sock->window.fin_seq, sock->window.next_seq_expected,
                   FIN_FLAG_MASK | ACK_FLAG_MASK);
}

/**
 * Starts closing: the FIN takes the next sequence number, so its ACK is
 * fin_seq + 1. Any data not yet sent is abandoned.
 */
static void start_close(cmu_socket_t *sock) {
  window_t *w = &sock->window;
  int64_t now = now_ms();

  w->fin_seq = w->able_to_send;
  w->able_to_send += 1;
  w->fin_resends = 0;
  w->fin_next_resend = now + FIN_GIVE_UP_MS / (FIN_RESENDS + 1);
  w->fin_give_up = now + FIN_GIVE_UP_MS;
  send_fin(sock);
  sock->state = STATE_WAITING_FOR_FIN_ACK;
}

/**
 * Receiver side of a FIN. If everything before it has arrived, the peer is
 * closed (it uses one sequence number). Always ACKs. Caller holds recv_lock.
 */
static void handle_fin(cmu_socket_t *sock, uint32_t seq) {
  window_t *w = &sock->window;
  if (!sock->peer_fin_received && seq == w->next_seq_expected) {
    w->next_seq_expected = seq + 1;
    sock->peer_fin_received = 1;
  }
  send_header_only(sock, w->able_to_send, w->next_seq_expected,
                   ACK_FLAG_MASK);
}

/**
 * Moves everything the application has written from sending_buf into the
 * backend's `unsent` queue.
 */
static void take_app_data(cmu_socket_t *sock) {
  window_t *w = &sock->window;

  while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
  }
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
  pthread_mutex_unlock(&(sock->send_lock));
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 * @param from Address the packet came from. Received packets never change
 *             `sock->conn`; only an accepted SYN does (in the handshake).
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt,
                    const struct sockaddr_in *from) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  if (sock->state == STATE_IDLE || sock->state == STATE_SYN_SENT ||
      sock->state == STATE_WAITING_FOR_ACK) {
    handle_handshake_message(sock, pkt, from);
    return;
  }

  // Client: a SYN-ACK after connecting means our final ACK may have been
  // lost, so ACK it again (same values as the original final ACK).
  if (sock->type == TCP_INITIATOR &&
      flags == (SYN_FLAG_MASK | ACK_FLAG_MASK)) {
    send_header_only(sock, sock->my_isn + 1, sock->peer_isn + 1,
                     ACK_FLAG_MASK);
    return;
  }

  // A packet can carry both an ACK and data: sender side first, then
  // receiver side.
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
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 *
 * @return 1 if a packet was received and handled, 0 otherwise (e.g. the
 *         `TIMEOUT` wait expired with nothing to read).
 */
int check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  struct sockaddr_in from;
  socklen_t conn_len = sizeof(from);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  int handled = 0;

  if (flags == TIMEOUT) {
    // Wait (without holding recv_lock) up to DEFAULT_TIMEOUT for a packet.
    struct pollfd ack_fd = {.fd = sock->socket, .events = POLLIN};
    if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
      return 0;
    }
    flags = NO_WAIT;
  }

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&from, &conn_len);
      break;
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&from,
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&from, &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt, &from);
    free(pkt);
    handled = 1;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return handled;
}

int cmu_handshake(cmu_socket_t *sock) {
  int attempts = 0;
  int64_t deadline = 0;

  if (sock->type == TCP_INITIATOR) {
    // Client: send SYN carrying my ISN.
    send_header_only(sock, sock->my_isn, 0, SYN_FLAG_MASK);
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
        // The SYN-ACK was just sent; start its timer.
        attempts = 1;
        deadline = now_ms() + DEFAULT_TIMEOUT;
      }
      continue;
    }

    // Wait only for the time left until the deadline, so packets that get
    // ignored don't push the timeout back.
    int64_t remaining = deadline - now_ms();
    if (remaining > 0) {
      struct pollfd pfd = {.fd = sock->socket, .events = POLLIN};
      if (poll(&pfd, 1, (int)remaining) > 0) {
        check_for_data(sock, NO_WAIT);
      }
      continue;
    }

    // Timed out: give up, or retransmit with the same ISN.
    if (attempts >= MAX_HANDSHAKE_ATTEMPTS) {
      if (sock->state == STATE_WAITING_FOR_ACK) {
        // Server: abandon this client and wait for a new SYN.
        sock->state = STATE_IDLE;
        sock->peer_isn = 0;
        continue;
      }
      return EXIT_ERROR;
    }
    if (sock->state == STATE_SYN_SENT) {
      send_header_only(sock, sock->my_isn, 0, SYN_FLAG_MASK);
    } else if (sock->state == STATE_WAITING_FOR_ACK) {
      send_header_only(sock, sock->my_isn, sock->peer_isn + 1,
                       SYN_FLAG_MASK | ACK_FLAG_MASK);
    }
    attempts++;
    deadline = now_ms() + DEFAULT_TIMEOUT;
  }

  // The SYN used up one sequence number in each direction, so data starts at
  // ISN + 1 on both sides.
  sock->window.oldest_pending = sock->my_isn + 1;
  sock->window.able_to_send = sock->my_isn + 1;
  sock->window.next_seq_expected = sock->peer_isn + 1;
  return EXIT_SUCCESS;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  window_t *w = &sock->window;
  int death, send_signal, peer_closed;

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    // 1. Take in new app data.
    take_app_data(sock);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    peer_closed = sock->peer_fin_received;
    pthread_mutex_unlock(&(sock->recv_lock));

    // Teardown.
    if (sock->state == STATE_CONNECTED && death) {
      int all_acked =
          w->unsent_len == 0 && w->oldest_pending == w->able_to_send;
      int gave_up = w->timeouts_without_ack >= MAX_HANDSHAKE_ATTEMPTS;
      if (all_acked || gave_up) {
        w->peer_closed_first = peer_closed;
        start_close(sock);
      }
    } else if (sock->state == STATE_WAITING_FOR_FIN_ACK) {
      int64_t now = now_ms();
      if (!before(w->oldest_pending, w->fin_seq + 1) || now >= w->fin_give_up) {
        // FIN ACKed, or out of time.
        if (w->peer_closed_first) {
          break;  // Both sides done; we were second.
        } else if (peer_closed) {
          sock->state = STATE_FINAL_WAIT;  // Peer's FIN came after ours.
          w->final_wait_end = now + FINAL_WAIT_MS;
        } else {
          sock->state = STATE_WAITING_FOR_PEER_FIN;
        }
      } else if (w->fin_resends < FIN_RESENDS && now >= w->fin_next_resend) {
        send_fin(sock);
        w->fin_resends++;
        w->fin_next_resend = now + FIN_GIVE_UP_MS / (FIN_RESENDS + 1);
      }
    } else if (sock->state == STATE_WAITING_FOR_PEER_FIN) {
      // Still receiving and ACKing the peer's data until its FIN arrives.
      if (peer_closed) {
        sock->state = STATE_FINAL_WAIT;
        w->final_wait_end = now_ms() + FINAL_WAIT_MS;
      }
    } else if (sock->state == STATE_FINAL_WAIT) {
      // Retransmitted FINs are re-ACKed by handle_fin().
      if (now_ms() >= w->final_wait_end) {
        break;
      }
    }

    // 2. Check for packets, waiting up to BACKEND_POLL_MS.
    struct pollfd pfd = {.fd = sock->socket, .events = POLLIN};
    if (poll(&pfd, 1, BACKEND_POLL_MS) > 0) {
      check_for_data(sock, NO_WAIT);
    }

    // 3. Send whatever fits in the window (not after our FIN). Receiving
    // the peer's FIN doesn't stop us sending our own data.
    if (sock->state == STATE_CONNECTED) {
      send_ready(sock);
    }

    // 4. Retransmit if the timer expired.
    check_timer(sock);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    send_signal = sock->received_len > 0 || sock->peer_fin_received;
    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  free_segments(w->in_flight);
  free_segments(w->out_of_order);
  free(w->unsent);

  pthread_exit(NULL);
  return NULL;
}
