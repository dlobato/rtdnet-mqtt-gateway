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

#include <json-c/json.h>
#include <modbus/modbus.h>
#include <mosquitto.h>
#include <time.h>
#include "gateway_config.h"
#include "mosquitto_helper.h"
#include "rtdnet.h"

typedef enum status {
  STATUS_CONNECTING,
  STATUS_CONNACK_RECVD
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
const size_t PUBLISH_PAYLOAD_MAX_SIZE = 64;
const char *UNIT_CONTROL_TOPIC_PREFIX = "unit-control";
const char *GROUP_TOPIC_PREFIX = "group";
const char *SET_TOPIC_PREFIX = "set";
const char *SET_TOPIC_VALUE_FIELD = "value";

static status_t status = STATUS_CONNECTING;

int int_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size) {
  return snprintf(payload, payload_max_size - 1, "{\"value\": %u}",
                  (unsigned int)value);
}

int int100_to_mqtt_payload(uint16_t value, char *payload,
                           int payload_max_size) {
  return snprintf(payload, payload_max_size - 1, "{\"value\": %.2f}",
                  (float)(value / 100.0));
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int rc) {
  struct gateway_ctx *ctx;
  int i, n;
  char topic[TOPIC_MAX_SIZE];

  assert(obj);
  ctx = (struct gateway_ctx *)obj;

  if (0 == rc) {
    status = STATUS_CONNACK_RECVD;
    // subscribe unit control set topics
    for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
      if (!unit_control_topics[i].set) {
        continue;
      }

      n = snprintf(topic, TOPIC_MAX_SIZE - 1, "%s/%s/%s/%s", ctx->cfg.id,
                   SET_TOPIC_PREFIX, UNIT_CONTROL_TOPIC_PREFIX,
                   unit_control_topics[i].name);
      if (n < 0 || n > (sizeof(topic) - 1)) {
        fprintf(stderr,
                "can't generate topic for %s register(too long?). Ignored\n",
                unit_control_topics[i].name);

        continue;
      }

      mosquitto_subscribe(mosq, NULL, topic, ctx->cfg.qos);
    }
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
  char *topic_name;
  char *token;
  char *save_ptr;
  struct json_object *jobj, *field;

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

  // split topic into parts to find out what it is requested
  // only clientId/set/* are considered valid (*=unit-control/[valid register])
  topic_name = strndup(message->topic, TOPIC_MAX_SIZE);

  // match clientId
  token = strtok_r(topic_name, "/", &save_ptr);
  if (!token || (strncmp(ctx->cfg.id, token, strlen(ctx->cfg.id)) != 0)) {
    goto my_message_callback_end;
  }

  // match set
  token = strtok_r(0, "/", &save_ptr);
  if (!token ||
      (strncmp(SET_TOPIC_PREFIX, token, strlen(SET_TOPIC_PREFIX)) != 0)) {
    goto my_message_callback_end;
  }

  // match [unit-control]
  token = strtok_r(0, "/", &save_ptr);
  if (token) {
    // match unit-control
    if (strncmp(UNIT_CONTROL_TOPIC_PREFIX, token,
                strlen(UNIT_CONTROL_TOPIC_PREFIX)) == 0) {
      token = strtok_r(0, "/", &save_ptr);
      if (!token) {
        goto my_message_callback_end;
      }
      for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
        if (strncmp(unit_control_topics[i].name, token,
                    strlen(unit_control_topics[i].name)) == 0) {
          if (!unit_control_topics[i].set) {
            break;
          }

          jobj = json_tokener_parse(message->payload);
          // printf("jobj from str:\n---\n%s\n---\n",
          //        json_object_to_json_string_ext(
          //            jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
          if (json_object_object_get_ex(jobj, SET_TOPIC_VALUE_FIELD, &field)) {
            int16_t value = json_object_get_int(field);
            rc = unit_control_topics[i].set(ctx->rtdnet_ctx, value);
            if (rc != 1) {
              fprintf(stderr, "Error setting unit control register: %s\n",
              rtdnet_strerror(errno));
            }
            //printf("set %s to %d\n", unit_control_topics[i].name, value);
          }
          json_object_put(jobj);

          break;
        }
      }
    }
  }

my_message_callback_end:
  free(topic_name);
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
  char payload[PUBLISH_PAYLOAD_MAX_SIZE];

  // unit-control
  for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic) - 1, "%s/%s/%s", cfg->id,
                 UNIT_CONTROL_TOPIC_PREFIX, unit_control_topics[i].name);
    if (n < 0 || n > (sizeof(topic) - 1)) {
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
    if (n < 0 || n > (sizeof(payload) - 1)) {
      fprintf(stderr,
              "can't generate payload for %s register(too long?). Ignored\n",
              unit_control_topics[i].name);

      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, false);
  }
}

void publish_group_registers(struct mosquitto *mosq, struct gateway_config *cfg,
                             uint16_t *regs) {
  int i, n;
  char topic[TOPIC_MAX_SIZE];
  char payload[PUBLISH_PAYLOAD_MAX_SIZE];

  // group
  for (i = 0; i < GROUP_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic) - 1, "%s/%s/%s", cfg->id,
                 GROUP_TOPIC_PREFIX, group_topics[i].name);
    if (n < 0 || n > (sizeof(topic) - 1)) {
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
    if (n < 0 || n > (sizeof(payload) - 1)) {
      fprintf(stderr,
              "can't generate payload for %s register(too long?). Ignored\n",
              group_topics[i].name);

      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, false);
  }
}

int main(int argc, char *argv[]) {
  struct gateway_ctx ctx;
  struct mosquitto *mosq = NULL;
  int rc;
  struct timespec last_publish = {0}, now;

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

  rc = client_connect(mosq, &ctx.cfg);
  if (rc) return rc;

  do {
    if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
      fprintf(stderr, "Error getting clock: %s\n", strerror(rc));
      return -1;
    }

    if (status == STATUS_CONNACK_RECVD &&
        ((now.tv_sec - last_publish.tv_sec) > ctx.cfg.publish_delay_s)) {
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
