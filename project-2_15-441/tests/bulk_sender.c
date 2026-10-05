/**
 * Test app: connects as an initiator, writes an entire file in one
 * cmu_write call, then closes.
 *
 * Usage: bulk_sender <file>
 * Server address comes from $server15441 / $serverport15441, like client.c.
 */

#include <stdio.h>
#include <stdlib.h>

#include "cmu_tcp.h"

int main(int argc, char **argv) {
  cmu_socket_t socket;
  char *serverip;
  char *serverport;
  FILE *fp;
  long size;
  uint8_t *buf;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <file>\n", argv[0]);
    return EXIT_FAILURE;
  }

  fp = fopen(argv[1], "rb");
  if (fp == NULL) {
    perror("fopen");
    return EXIT_FAILURE;
  }
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  buf = malloc(size);
  if (fread(buf, 1, size, fp) != (size_t)size) {
    perror("fread");
    return EXIT_FAILURE;
  }
  fclose(fp);

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }
  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }

  if (cmu_socket(&socket, TCP_INITIATOR, atoi(serverport), serverip) < 0) {
    return EXIT_FAILURE;
  }
  cmu_write(&socket, buf, size);
  free(buf);

  if (cmu_close(&socket) < 0) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
