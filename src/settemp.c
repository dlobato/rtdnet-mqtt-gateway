#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "rtdnet.h"

#define SERVER_ADDRESS 1

void usage() { printf("Usage: rtdnet-set-temp temp-value(in [16-32])\n"); }

int main(int argc, char *argv[]) {
  int rc;
  uint16_t set_temp;
  rtdnet_t *ctx = NULL;

  if (argc < 2) {
    usage();
    return -1;
  }

  set_temp = atoi(argv[1]);
  if (set_temp < UNIT_CONTROL_SETPOINT_MIN ||
      set_temp > UNIT_CONTROL_SETPOINT_MAX) {
    usage();
    return -1;
  }

  ctx = rtdnet_new(SERVER_ADDRESS, "/dev/ttyUSB0", 9600, 'N', 8, 1);
  if (ctx == NULL) {
    fprintf(stderr, "Unable to allocate rtdnet context: %s\n",
            rtdnet_strerror(errno));
    return -1;
  }

  printf("Setting temp...\n");
  rc = rtdnet_write_unit_control_setpoint(ctx, set_temp);
  if (rc == -1) {
    fprintf(stderr, "Error setting unit control setpoint: %s\n",
            rtdnet_strerror(errno));
    return -1;
  }

  return 0;
}