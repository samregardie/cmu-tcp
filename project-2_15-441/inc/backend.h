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
 * This file defines the function signatures for the CMU-TCP backend that should
 * be exposed. The backend runs in a different thread and handles all the socket
 * operations separately from the application.
 */

#ifndef PROJECT_2_15_441_INC_BACKEND_H_
#define PROJECT_2_15_441_INC_BACKEND_H_

#include "cmu_tcp.h"

/**
 * Launches the CMU-TCP backend.
 *
 * @param in the socket to be used for backend processing.
 */
void* begin_backend(void* in);

/**
 * Runs the connection handshake. Blocks until the socket is connected.
 *
 * @param sock The socket to connect. `my_isn` must already be set.
 *
 * @return 0 on success, -1 on error.
 */
int cmu_handshake(cmu_socket_t* sock);

#endif  // PROJECT_2_15_441_INC_BACKEND_H_
