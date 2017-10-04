#include <errno.h>
#include <stdio.h>
#include "rtdnet.h"

#define SERVER_ADDRESS 1

const char* unit_control_regs_names[UNIT_CONTROL_REGISTERS_MAX] = {
    "SETPOINT", "FANSPEED", "MODE", "LOUVRE", "ONOFF",
};

const char* rc_regs_names[RC_REGISTERS_MAX] = {"TEMPERATURE", "OPERATION_MODE"};

const char* group_regs1_names[GROUP_REGISTERS1_MAX] = {
    "UNIT_COUNT",   "IS_FAULT",       "FAULT_CODE",     "RETURN_AIR_AVG",
    "FILTER_ALARM", "RETURN_AIR_MIN", "RETURN_AIR_MAX",
};

const char* unit_regs1_names[UNIT_REGISTERS1_MAX] = {
    "UNIT_EXISTS", "IS_FAULT", "FAULT_CODE", "RETURN_AIR_TEMPERATURE",
    "FILTER_ALARM"};

int main(int argc, char* argv[]) {
  int i, j;
  int rc;
  rtdnet_t* ctx = NULL;

  uint16_t unit_control_regs[UNIT_CONTROL_REGISTERS_MAX] = {0};
  uint16_t rc_regs[RC_REGISTERS_MAX] = {0};
  uint16_t group_regs1[GROUP_REGISTERS1_MAX] = {0};
  uint16_t unit_regs1[UNIT_REGISTERS1_MAX] = {0};

  ctx = rtdnet_new(SERVER_ADDRESS, "/dev/ttyUSB0", 9600, 'N', 8, 1);
  if (ctx == NULL) {
    fprintf(stderr, "Unable to allocate rtdnet context: %s\n", rtdnet_strerror(errno));
    return -1;
  }

  // read control registers (holding registers)
  printf("Reading Unit control registers...\n");
  rc = rtdnet_read_unit_control_registers(ctx, unit_control_regs);
  if (rc != UNIT_CONTROL_REGISTERS_MAX) {
    fprintf(stderr, "Error reading unit control registers: %s\n", rtdnet_strerror(errno));
    return -1;
  }

  for (i = 0; i < rc; i++) {
    printf("%s(H%04d)=%d (0x%X)\n", unit_control_regs_names[i],
           UNIT_CONTROL_REGISTERS_START_ADDR + i, unit_control_regs[i],
           unit_control_regs[i]);
  }

  // read rc registers (input registers)
  printf("Reading RC registers...\n");
  rc = rtdnet_read_rc_registers(ctx, rc_regs);
  if (rc != RC_REGISTERS_MAX) {
    fprintf(stderr, "Error reading rc registers: %s\n", rtdnet_strerror(errno));
    return -1;
  }

  for (i = 0; i < rc; i++) {
    printf("%s(I%04d)=%d (0x%X)\n", rc_regs_names[i], RC_REGISTERS_START_ADDR + i,
           rc_regs[i], rc_regs[i]);
  }

  // read group registers (input registers)
  printf("Reading Group registers1...\n");
  rc = rtdnet_read_group_registers1(ctx, group_regs1);
  if (rc != GROUP_REGISTERS1_MAX) {
    fprintf(stderr, "Error reading group registers1: %s\n", rtdnet_strerror(errno));
    return -1;
  }

  for (i = 0; i < rc; i++) {
    printf("%s(I%04d)=%d (0x%X)\n", group_regs1_names[i],
           GROUP_REGISTERS_START_ADDR + i, group_regs1[i], group_regs1[i]);
  }

  // read units registers (input registers)
  for (i = 0; i < group_regs1[GROUP_UNIT_COUNT]; i++) {
    printf("Reading Unit %d registers...\n", i);
    rc = rtdnet_read_unit_registers1(ctx, i, unit_regs1);
    if (rc != UNIT_REGISTERS1_MAX) {
      fprintf(stderr, "Error reading unit %d registers1: %s\n", i, rtdnet_strerror(errno));
      return -1;
    }

    for (j = 0; j < rc; j++) {
      printf("%s(I%04d)=%d (0x%X)\n", unit_regs1_names[j],
             UNIT_REGISTERS_START_ADDR(i) + j, unit_regs1[j], unit_regs1[j]);
    }
  }

  return 0;
}