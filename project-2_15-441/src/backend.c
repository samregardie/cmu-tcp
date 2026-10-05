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

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
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
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
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

  if (sock->state != STATE_CONNECTED) {
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

  switch (flags) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
    default: {
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
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

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&from, &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
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

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }
      free(msg);

      data_offset += payload_len;
    }
  }
}

/**
 * Current time on a monotonic clock, in milliseconds.
 */
static int64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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
  sock->window.last_ack_received = sock->my_isn + 1;
  sock->window.next_seq_expected = sock->peer_isn + 1;
  return EXIT_SUCCESS;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
