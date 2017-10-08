#ifndef RTDNET_H
#define RTDNET_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UNIT_CONTROL_REGISTERS_START_ADDR 1
#define RC_REGISTERS_START_ADDR 50
#define GROUP_REGISTERS_START_ADDR 20
#define UNIT_REGISTERS_START_ADDR(i) (((i + 1) * 100) + GROUP_REGISTERS_START_ADDR)

#define UNIT_CONTROL_SETPOINT_MIN ((uint8_t)16)
#define UNIT_CONTROL_SETPOINT_MAX ((uint8_t)32)
#define UNIT_CONTROL_FANSPEED_MIN ((uint8_t)1)
#define UNIT_CONTROL_FANSPEED_MAX ((uint8_t)3)
#define UNIT_CONTROL_MODE_MIN ((uint8_t)0)
#define UNIT_CONTROL_MODE_MAX ((uint8_t)4)
#define UNIT_CONTROL_LOUVRE_MIN ((uint8_t)1)
#define UNIT_CONTROL_LOUVRE_MAX ((uint8_t)7)
#define UNIT_CONTROL_ONOFF_MIN ((uint8_t)0)
#define UNIT_CONTROL_ONOFF_MAX ((uint8_t)1)


enum unit_control_registers_addr_offset {
  UNIT_CONTROL_SETPOINT,
  UNIT_CONTROL_FANSPEED,
  UNIT_CONTROL_MODE,
  UNIT_CONTROL_LOUVRE,
  UNIT_CONTROL_ONOFF,
  UNIT_CONTROL_REGISTERS_MAX
};

enum rc_regs_addr_offset {
  RC_TEMPERATURE,
  RC_OPERATION_MODE,
  RC_REGISTERS_MAX
};

enum group_registers1_addr_offset {
  GROUP_UNIT_COUNT,
  GROUP_IS_FAULT,
  GROUP_FAULT_CODE,
  GROUP_RETURN_AIR_AVG,
  GROUP_FILTER_ALARM,
  GROUP_RETURN_AIR_MIN,
  GROUP_RETURN_AIR_MAX,
  GROUP_REGISTERS1_MAX
};

enum unit_registers1_addr_offset {
  UNIT_EXISTS,
  UNIT_IS_FAULT,
  UNIT_FAULT_CODE,
  UNIT_RETURN_AIR_AVG,
  UNIT_FILTER_ALARM,
  UNIT_REGISTERS1_MAX
};

typedef struct _rtdnet rtdnet_t;

rtdnet_t* rtdnet_new(int addr, const char* device, int baud, char parity,
                     int data_bit, int stop_bit, int debug);

const char *rtdnet_strerror(int errnum);

int rtdnet_read_unit_control_registers(rtdnet_t* ctx, uint16_t* dest);
int rtdnet_read_rc_registers(rtdnet_t* ctx, uint16_t* dest);
int rtdnet_read_group_registers1(rtdnet_t* ctx, uint16_t* dest);
int rtdnet_read_unit_registers1(rtdnet_t* ctx, uint16_t unit, uint16_t* dest);

int rtdnet_write_unit_control_setpoint(rtdnet_t* ctx, uint16_t new_value);
int rtdnet_write_unit_control_fanspeed(rtdnet_t* ctx, uint16_t new_value);
int rtdnet_write_unit_control_mode(rtdnet_t* ctx, uint16_t new_value);
int rtdnet_write_unit_control_louvre(rtdnet_t* ctx, uint16_t new_value);
int rtdnet_write_unit_control_onoff(rtdnet_t* ctx, uint16_t new_value);

#ifdef __cplusplus
}
#endif

#endif  // RTDNET_H