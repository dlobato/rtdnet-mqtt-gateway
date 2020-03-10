/*

Based on mosquitto_pub

*/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <modbus/modbus.h>
#include <mosquitto.h>
#include <time.h>
#include <inttypes.h>
#include "gateway_config.h"
#include "mosquitto_helper.h"
#include "rtdnet.h"

typedef enum status {
  STATUS_CONNECTING,
  STATUS_READY,
  STATUS_FORCE_PUBLISH
} status_t;

typedef int (*rtdnet_write_register_f)(rtdnet_t *ctx, uint16_t new_value);
typedef int (*to_mqtt_payload_f)(uint16_t value, char *payload,
                                 int payload_max_size);

struct gateway_ctx {
  struct gateway_config cfg;
  rtdnet_t *rtdnet_ctx;
};


struct topic_definition {
  char *name;
  uint8_t offset;
  rtdnet_write_register_f set;
  to_mqtt_payload_f to_mqtt_payload;
};

// forward declarations
int int_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size);
int int100_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size);


const struct topic_definition unit_control_topics[] = {
    {"setpoint", UNIT_CONTROL_SETPOINT, rtdnet_write_unit_control_setpoint,
     int_to_mqtt_payload},
    {"fanspeed", UNIT_CONTROL_FANSPEED, rtdnet_write_unit_control_fanspeed,
     int_to_mqtt_payload},
    {"mode", UNIT_CONTROL_MODE, rtdnet_write_unit_control_mode,
     int_to_mqtt_payload},
    {"louvre", UNIT_CONTROL_LOUVRE, rtdnet_write_unit_control_louvre,
     int_to_mqtt_payload},
    {"onoff", UNIT_CONTROL_ONOFF, rtdnet_write_unit_control_onoff,
     int_to_mqtt_payload},
};
const size_t UNIT_CONTROL_TOPICS_COUNT =
    sizeof(unit_control_topics) / sizeof(struct topic_definition);

const struct topic_definition group_topics[] = {
    {"group-unit-count", GROUP_UNIT_COUNT, NULL, int_to_mqtt_payload},
    {"is-fault", GROUP_IS_FAULT, NULL, int_to_mqtt_payload},
    {"fault-code", GROUP_FAULT_CODE, NULL, int_to_mqtt_payload},
    {"return-air-avg", GROUP_RETURN_AIR_AVG, NULL, int100_to_mqtt_payload},
    {"filter-alarm", GROUP_FILTER_ALARM, NULL, int_to_mqtt_payload},
    {"return-air-min", GROUP_RETURN_AIR_MIN, NULL, int100_to_mqtt_payload},
    {"return-air-max", GROUP_RETURN_AIR_MAX, NULL, int100_to_mqtt_payload},
};
const size_t GROUP_TOPICS_COUNT =
    sizeof(group_topics) / sizeof(struct topic_definition);

const size_t TOPIC_MAX_SIZE = 64;
const size_t PAYLOAD_VALUE_BUFFER_SIZE = 8;//all values are uint16_t
const char *STATUS_TOPIC_PREFIX = "status";
const char *STATUS_ONLINE = "online";
const char *STATUS_OFFLINE = "offline";
const char *UNIT_CONTROL_TOPIC_PREFIX = "unit-control";
const char *GROUP_TOPIC_PREFIX = "group";
const char *SET_TOPIC_PREFIX = "set";

static status_t status = STATUS_CONNECTING;

int int_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size) {
  return snprintf(payload, payload_max_size - 1, "%" PRIu16, value);
}

int int100_to_mqtt_payload(uint16_t value, char *payload,
                           int payload_max_size) {
  return snprintf(payload, payload_max_size - 1, "%.2f",
                  (float)(value / 100.0));
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int rc) {
  struct gateway_ctx *ctx;
  int i, n;
  char topic[TOPIC_MAX_SIZE];

  assert(obj);
  ctx = (struct gateway_ctx *)obj;

  if (0 == rc) {
    status = STATUS_READY;
    // subscribe unit control set topics
    for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
      if (!unit_control_topics[i].set) {
        continue;
      }

      n = snprintf(topic, sizeof(topic), "%s/%s/%s/%s", ctx->cfg.id,
                   SET_TOPIC_PREFIX, UNIT_CONTROL_TOPIC_PREFIX,
                   unit_control_topics[i].name);
      if (n < 0 || n > sizeof(topic)) {
        fprintf(stderr,
                "can't generate topic for %s register(too long?). Ignored\n",
                unit_control_topics[i].name);

        continue;
      }

      mosquitto_subscribe(mosq, NULL, topic, ctx->cfg.qos);
    }

    snprintf(topic, sizeof(topic), "%s/%s", ctx->cfg.id, STATUS_TOPIC_PREFIX);
    mosquitto_publish(mosq, NULL, topic, strlen(STATUS_ONLINE), STATUS_ONLINE, 0, true);
  } else {
    fprintf(stderr, "%s\n", mosquitto_connack_string(rc));
  }
}

// void my_publish_callback(struct mosquitto *mosq, void *obj, int mid) {
//   struct gateway_ctx *ctx;

//   assert(obj);
//   ctx = (struct gateway_ctx *)obj;
// }

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid,
                           int qos_count, const int *granted_qos) {
  int i;

  printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
  for (i = 1; i < qos_count; i++) {
    printf(", %d", granted_qos[i]);
  }
  printf("\n");
}

void my_message_callback(struct mosquitto *mosq, void *obj,
                         const struct mosquitto_message *message) {
  struct gateway_ctx *ctx;
  int i,rc;
  char topic_name[TOPIC_MAX_SIZE];
  char payload_buf[PAYLOAD_VALUE_BUFFER_SIZE];
  char *token;
  char *save_ptr;

  assert(obj);
  ctx = (struct gateway_ctx *)obj;

  if (ctx->cfg.debug) {
    if (message->payloadlen) {
      printf("%s ", message->topic);
      fwrite(message->payload, 1, message->payloadlen, stdout);
      printf("\n");
    } else {
      printf("%s (null)\n", message->topic);
    }
    fflush(stdout);
  }

  if (strlen(message->topic) > (sizeof(topic_name) -1 )) {
    fprintf(stderr, "Topic too big, ignored: topicn=%s\n", message->topic);
    return;
  }

  if (message->payloadlen > (PAYLOAD_VALUE_BUFFER_SIZE - 1)) {
    fprintf(stderr, "Payload too big, ignored: payloadlen=%d\n", message->payloadlen);
    return;
  }

  // split topic into parts to find out what it is requested
  // only clientId/set/* are considered valid (*=unit-control/[valid register])
  strncpy(topic_name, message->topic, sizeof(topic_name));

  // match clientId
  token = strtok_r(topic_name, "/", &save_ptr);
  if (!token || (strncmp(ctx->cfg.id, token, strlen(ctx->cfg.id)) != 0)) {
    return;
  }

  // match set
  token = strtok_r(0, "/", &save_ptr);
  if (!token ||
      (strncmp(SET_TOPIC_PREFIX, token, strlen(SET_TOPIC_PREFIX)) != 0)) {
    return;
  }

  // match [unit-control]
  token = strtok_r(0, "/", &save_ptr);
  if (token) {
    // match unit-control
    if (strncmp(UNIT_CONTROL_TOPIC_PREFIX, token,
                strlen(UNIT_CONTROL_TOPIC_PREFIX)) == 0) {
      token = strtok_r(0, "/", &save_ptr);
      if (!token) {
        return;
      }
      for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
        if (strncmp(unit_control_topics[i].name, token,
                    strlen(unit_control_topics[i].name)) == 0) {
          if (!unit_control_topics[i].set) {
            return;
          }

          memcpy(payload_buf, message->payload, message->payloadlen);
          payload_buf[message->payloadlen] = '\0';
          int16_t value;
          if (sscanf(payload_buf, "%" SCNu16, &value) == 1) {
            rc = unit_control_topics[i].set(ctx->rtdnet_ctx, value);
            if (rc != 1) {
              fprintf(stderr, "Error setting unit control register: %s\n",
              rtdnet_strerror(errno));
            }
          }

          status = STATUS_FORCE_PUBLISH;
          return;
        }
      }
    }
  }
}

void my_log_callback(struct mosquitto *mosq, void *obj, int level,
                     const char *str) {
  printf("%s\n", str);
}

void publish_unit_control_registers(struct mosquitto *mosq,
                                    struct gateway_config *cfg,
                                    uint16_t *regs) {
  int i, n;
  char topic[TOPIC_MAX_SIZE];
  char payload[PAYLOAD_VALUE_BUFFER_SIZE];

  // unit-control
  for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic), "%s/%s/%s", cfg->id,
                 UNIT_CONTROL_TOPIC_PREFIX, unit_control_topics[i].name);
    if (n < 0 || n > sizeof(topic)) {
      fprintf(stderr,
              "can't generate topic for %s register(too long?). Ignored\n",
              unit_control_topics[i].name);

      continue;
    }
    if (!unit_control_topics[i].to_mqtt_payload) {
      continue;
    }
    n = unit_control_topics[i].to_mqtt_payload(
        regs[unit_control_topics[i].offset], payload, sizeof(payload));
    if (n < 0 || n > sizeof(payload)) {
      fprintf(stderr,
              "can't generate payload for %s register(too long?). Ignored\n",
              unit_control_topics[i].name);

      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, true);
  }
}

void publish_group_registers(struct mosquitto *mosq, struct gateway_config *cfg,
                             uint16_t *regs) {
  int i, n;
  char topic[TOPIC_MAX_SIZE];
  char payload[PAYLOAD_VALUE_BUFFER_SIZE];

  // group
  for (i = 0; i < GROUP_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic), "%s/%s/%s", cfg->id,
                 GROUP_TOPIC_PREFIX, group_topics[i].name);
    if (n < 0 || n > sizeof(topic)) {
      fprintf(stderr,
              "can't generate topic for %s register(too long?). Ignored\n",
              group_topics[i].name);

      continue;
    }
    if (!group_topics[i].to_mqtt_payload) {
      continue;
    }
    n = group_topics[i].to_mqtt_payload(regs[group_topics[i].offset], payload,
                                        sizeof(payload));
    if (n < 0 || n > sizeof(payload)) {
      fprintf(stderr,
              "can't generate payload for %s register(too long?). Ignored\n",
              group_topics[i].name);

      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, true);
  }
}

int main(int argc, char *argv[]) {
  struct gateway_ctx ctx;
  struct mosquitto *mosq = NULL;
  int rc;
  struct timespec last_publish = {0}, now;
  char topic[TOPIC_MAX_SIZE];

  uint16_t unit_control_regs[UNIT_CONTROL_REGISTERS_MAX] = {0};
  uint16_t group_regs1[GROUP_REGISTERS1_MAX] = {0};

  memset(&ctx.cfg, 0, sizeof(struct gateway_config));
  rc = gateway_config_load(&ctx.cfg, argc, argv);
  if (rc) {
    gateway_config_cleanup(&ctx.cfg);
    if (rc == 2) {
      /* --help */
      gateway_config_usage();
    } else {
      fprintf(stderr, "\nUse 'rtdnet-mqtt-gateway --help' to see usage.\n");
    }
    return 1;
  }

  ctx.rtdnet_ctx = rtdnet_new(ctx.cfg.server_addr, ctx.cfg.device, ctx.cfg.baud, ctx.cfg.parity,
    ctx.cfg.data_bit, ctx.cfg.stop_bit, ctx.cfg.debug);
  if (ctx.rtdnet_ctx == NULL) {
    fprintf(stderr, "Unable to allocate rtdnet context: %s\n",
            rtdnet_strerror(errno));
    return -1;
  }

  mosquitto_lib_init();

  mosq = mosquitto_new(ctx.cfg.id, true, &ctx.cfg);
  if (!mosq) {
    switch (errno) {
      case ENOMEM:
        fprintf(stderr, "Error: Out of memory.\n");
        break;
      case EINVAL:
        fprintf(stderr, "Error: Invalid id.\n");
        break;
    }
    mosquitto_lib_cleanup();
    return 1;
  }

  if (client_opts_set(mosq, &ctx.cfg)) {
    return 1;
  }

  if (ctx.cfg.debug) {
    mosquitto_log_callback_set(mosq, my_log_callback);
    mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
  }

  mosquitto_connect_callback_set(mosq, my_connect_callback);
  // mosquitto_publish_callback_set(mosq, my_publish_callback);
  mosquitto_message_callback_set(mosq, my_message_callback);
  snprintf(topic, sizeof(topic), "%s/%s", ctx.cfg.id, STATUS_TOPIC_PREFIX);
  mosquitto_will_set(mosq, topic, strlen(STATUS_OFFLINE), STATUS_OFFLINE, 0, true);

  rc = client_connect(mosq, &ctx.cfg);
  if (rc) return rc;

  do {
    if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
      fprintf(stderr, "Error getting clock: %s\n", strerror(rc));
      return -1;
    }

    if (status == STATUS_FORCE_PUBLISH ||
        (status == STATUS_READY &&
         ((now.tv_sec - last_publish.tv_sec) > ctx.cfg.publish_delay_s))) {
      // get unit-control registers to publish them
      rc = rtdnet_read_unit_control_registers(ctx.rtdnet_ctx, unit_control_regs);
      if (rc != UNIT_CONTROL_REGISTERS_MAX) {
        fprintf(stderr, "Error reading unit control registers: %s\n",
                rtdnet_strerror(errno));
        return -1;
      }
      publish_unit_control_registers(mosq, &ctx.cfg, unit_control_regs);

      // get group registers to publish them
      rc = rtdnet_read_group_registers1(ctx.rtdnet_ctx, group_regs1);
      if (rc != GROUP_REGISTERS1_MAX) {
        fprintf(stderr, "Error reading group registers1: %s\n",
                rtdnet_strerror(errno));
        return -1;
      }
      publish_group_registers(mosq, &ctx.cfg, group_regs1);
      last_publish = now;
      status = STATUS_READY;
    }
    rc = mosquitto_loop(mosq, -1, 1);
  } while (rc == MOSQ_ERR_SUCCESS);

  mosquitto_destroy(mosq);
  mosquitto_lib_cleanup();

  if (rc) {
    fprintf(stderr, "Error: %s\n", mosquitto_strerror(rc));
  }
  return rc;
}
