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
 * This file defines the API for the CMU TCP implementation.
 */

#ifndef PROJECT_2_15_441_INC_CMU_TCP_H_
#define PROJECT_2_15_441_INC_CMU_TCP_H_

#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "grading.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

/**
 * Connection states
 *   Client: IDLE --(send SYN)--> SYN_SENT --(SYN-ACK, send ACK)--> CONNECTED
 *   Server: IDLE --(SYN, send SYN-ACK)--> WAITING_FOR_ACK --(ACK)--> CONNECTED
 */
typedef enum {
  STATE_IDLE = 0,
  STATE_SYN_SENT,
  STATE_WAITING_FOR_ACK,
  STATE_CONNECTED,
} cmu_conn_state_t;

/**
 * A run of bytes and its starting sequence number. Used for sent packets kept
 * until acked, and for out-of-order data kept until the gap before it fills.
 */
typedef struct segment {
  uint32_t seq;
  uint16_t len;
  uint8_t* data;
  struct segment* next;
} segment_t;

/**
 * An ACK number N means every byte before N has been received; N is the next
 * byte expected.
 */
typedef struct {
  // Sender state (backend thread only).
  uint32_t oldest_pending;     // Oldest byte not yet acked.
  uint32_t able_to_send;       // Next new byte to send (lowest unsent seq).
  segment_t* in_flight;        // Sent packets not fully acked, oldest first.
  segment_t* in_flight_tail;
  uint8_t* unsent;             // App data taken from sending_buf, not sent.
  int unsent_off;              // Bytes of `unsent` already sent.
  int unsent_len;              // Total bytes in `unsent`.
  int timer_running;
  int64_t timer_deadline;      // Monotonic ms.

  // Receiver state (backend thread, under recv_lock).
  uint32_t next_seq_expected;  // The ACK number we send.
  segment_t* out_of_order;     // Received past a gap, sorted by seq.
} window_t;

/**
 * CMU-TCP socket types. (DO NOT CHANGE.)
 */
typedef enum {
  TCP_INITIATOR = 0,
  TCP_LISTENER = 1,
} cmu_socket_type_t;

/**
 * This structure holds the state of a socket. You may modify this structure as
 * you see fit to include any additional state you need for your implementation.
 */
typedef struct {
  int socket;
  pthread_t thread_id;
  uint16_t my_port;
  struct sockaddr_in conn;
  uint8_t* received_buf;
  int received_len;
  pthread_mutex_t recv_lock;
  pthread_cond_t wait_cond;
  uint8_t* sending_buf;
  int sending_len;
  cmu_socket_type_t type;
  pthread_mutex_t send_lock;
  int dying;
  pthread_mutex_t death_lock;
  window_t window;
  cmu_conn_state_t state;
  uint32_t my_isn;
  uint32_t peer_isn;
} cmu_socket_t;

/*
 * DO NOT CHANGE THE DECLARATIONS BELOW
 */

/**
 * Read mode flags supported by a CMU-TCP socket.
 */
typedef enum {
  NO_FLAG = 0,  // Default behavior: block indefinitely until data is available.
  NO_WAIT,      // Return immediately if no data is available.
  TIMEOUT,      // Block until data is available or the timeout is reached.
} cmu_read_mode_t;

/**
 * Constructs a CMU-TCP socket.
 *
 * An Initiator socket is used to connect to a Listener socket.
 *
 * @param sock The structure with the socket state. It will be initialized by
 *             this function.
 * @param socket_type Indicates the type of socket: Listener or Initiator.
 * @param port Port to either connect to, or bind to. (Based on socket_type.)
 * @param server_ip IP address of the server to connect to. (Only used if the
 *                 socket is an initiator.)
 *
 * @return 0 on success, -1 on error.
 */
int cmu_socket(cmu_socket_t* sock, const cmu_socket_type_t socket_type,
               const int port, const char* server_ip);

/**
 * Closes a CMU-TCP socket.
 *
 * @param sock The socket to close.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_close(cmu_socket_t* sock);

/**
 * Reads data from a CMU-TCP socket.
 *
 * If there is data available in the socket buffer, it is placed in the
 * destination buffer.
 *
 * @param sock The socket to read from.
 * @param buf The buffer to read into.
 * @param length The maximum number of bytes to read.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information. `TIMEOUT` is not
 *             implemented for CMU-TCP.
 *
 * @return The number of bytes read on success, -1 on error.
 */
int cmu_read(cmu_socket_t* sock, void* buf, const int length,
             cmu_read_mode_t flags);

/**
 * Writes data to a CMU-TCP socket.
 *
 * @param sock The socket to write to.
 * @param buf The data to write.
 * @param length The number of bytes to write.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_write(cmu_socket_t* sock, const void* buf, int length);

/*
 * You can declare more functions after this point if you need to.
 */

#endif  // PROJECT_2_15_441_INC_CMU_TCP_H_
