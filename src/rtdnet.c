#include "rtdnet.h"
#include <modbus/modbus.h>
#include <errno.h>
#include <stdlib.h>

struct _rtdnet {
  modbus_t* modbus_ctx;
};

rtdnet_t* rtdnet_new(int addr, const char* device, int baud, char parity,
                     int data_bit, int stop_bit) {
  rtdnet_t* ctx = NULL;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    errno = ENOMEM;
    return NULL;
  }

  ctx->modbus_ctx = modbus_new_rtu(device, baud, parity, data_bit, stop_bit);
  if (ctx->modbus_ctx == NULL) {
    errno = ENOMEM;
    free(ctx);
    return NULL;
  }

  modbus_set_debug(ctx->modbus_ctx, TRUE);
  modbus_set_error_recovery(
      ctx->modbus_ctx,
      MODBUS_ERROR_RECOVERY_LINK | MODBUS_ERROR_RECOVERY_PROTOCOL);
  modbus_set_slave(ctx->modbus_ctx, addr);

  if (modbus_connect(ctx->modbus_ctx) == -1) {
    modbus_free(ctx->modbus_ctx);
    free(ctx);
    return NULL;
  }

  return ctx;
}

const char *rtdnet_strerror(int errnum) {
  return modbus_strerror(errnum);
}

int rtdnet_read_registers(rtdnet_t* ctx, int addr, int nb, uint16_t* dest) {
  return modbus_read_registers(ctx->modbus_ctx, addr, nb, dest);
}

int rtdnet_read_input_registers(rtdnet_t* ctx, int addr, int nb,
                                uint16_t* dest) {
  return modbus_read_input_registers(ctx->modbus_ctx, addr, nb, dest);
}

int rtdnet_write_register(rtdnet_t* ctx, int addr, uint16_t new_value) {
  return modbus_write_register(ctx->modbus_ctx, addr, new_value);
}

int rtdnet_read_unit_control_registers(rtdnet_t* ctx, uint16_t* dest) {
  return rtdnet_read_registers(ctx, UNIT_CONTROL_REGISTERS_START_ADDR,
                               UNIT_CONTROL_REGISTERS_MAX, dest);
}

int rtdnet_read_rc_registers(rtdnet_t* ctx, uint16_t* dest) {
  return rtdnet_read_input_registers(ctx, RC_REGISTERS_START_ADDR,
                                     RC_REGISTERS_MAX, dest);
}

int rtdnet_read_group_registers1(rtdnet_t* ctx, uint16_t* dest) {
  return rtdnet_read_input_registers(ctx, GROUP_REGISTERS_START_ADDR,
                                     GROUP_REGISTERS1_MAX, dest);
}

int rtdnet_read_unit_registers1(rtdnet_t* ctx, uint16_t unit, uint16_t* dest) {
  return rtdnet_read_input_registers(ctx, (uint16_t)UNIT_REGISTERS_START_ADDR(unit),
                                     UNIT_REGISTERS1_MAX, dest);
}

int rtdnet_write_unit_control_setpoint(rtdnet_t* ctx, uint16_t new_value) {
  if (new_value < UNIT_CONTROL_SETPOINT_MIN || new_value > UNIT_CONTROL_SETPOINT_MAX) {
    errno = EINVAL;
    return -1;
  }
  return rtdnet_write_register(
      ctx, UNIT_CONTROL_REGISTERS_START_ADDR + UNIT_CONTROL_SETPOINT,
      new_value);
}

int rtdnet_write_unit_control_fanspeed(rtdnet_t* ctx, uint16_t new_value) {
  if (new_value < UNIT_CONTROL_FANSPEED_MIN || new_value > UNIT_CONTROL_FANSPEED_MAX) {
    errno = EINVAL;
    return -1;
  }
  return rtdnet_write_register(
      ctx, UNIT_CONTROL_REGISTERS_START_ADDR + UNIT_CONTROL_FANSPEED,
      new_value);
}

int rtdnet_write_unit_control_mode(rtdnet_t* ctx, uint16_t new_value) {
  if (new_value < UNIT_CONTROL_MODE_MIN || new_value > UNIT_CONTROL_MODE_MAX) {
    errno = EINVAL;
    return -1;
  }
  return rtdnet_write_register(
      ctx, UNIT_CONTROL_REGISTERS_START_ADDR + UNIT_CONTROL_MODE, new_value);
}

int rtdnet_write_unit_control_louvre(rtdnet_t* ctx, uint16_t new_value) {
  if (new_value < UNIT_CONTROL_LOUVRE_MIN || new_value > UNIT_CONTROL_LOUVRE_MAX) {
    errno = EINVAL;
    return -1;
  }
  return rtdnet_write_register(
      ctx, UNIT_CONTROL_REGISTERS_START_ADDR + UNIT_CONTROL_LOUVRE, new_value);
}

int rtdnet_write_unit_control_onoff(rtdnet_t* ctx, uint16_t new_value) {
  if (new_value < UNIT_CONTROL_ONOFF_MIN || new_value > UNIT_CONTROL_ONOFF_MAX) {
    errno = EINVAL;
    return -1;
  }
  return rtdnet_write_register(
      ctx, UNIT_CONTROL_REGISTERS_START_ADDR + UNIT_CONTROL_ONOFF, new_value);
}
