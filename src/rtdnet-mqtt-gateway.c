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
#include "client_shared.h"
#include "rtdnet.h"

#define STATUS_CONNECTING 0
#define STATUS_CONNACK_RECVD 1

#define SERVER_ADDRESS 1

typedef int (*rtdnet_write_register_f)(rtdnet_t *ctx, uint16_t new_value);
typedef int (*to_mqtt_payload_f)(uint16_t value, char *payload, int payload_max_size);

int int_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size);
int int100_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size);

struct topic_definition {
  char *name;
  uint8_t offset;
  rtdnet_write_register_f set;
  to_mqtt_payload_f to_mqtt_payload;
};

const struct topic_definition unit_control_topics[] = {
    {"setpoint", UNIT_CONTROL_SETPOINT, rtdnet_write_unit_control_setpoint, int_to_mqtt_payload},
    {"fanspeed", UNIT_CONTROL_FANSPEED, rtdnet_write_unit_control_fanspeed, int_to_mqtt_payload},
    {"mode", UNIT_CONTROL_MODE, rtdnet_write_unit_control_mode, int_to_mqtt_payload},
    {"louvre", UNIT_CONTROL_LOUVRE, rtdnet_write_unit_control_louvre, int_to_mqtt_payload},
    {"onoff", UNIT_CONTROL_ONOFF, rtdnet_write_unit_control_onoff, int_to_mqtt_payload},
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

static int status = STATUS_CONNECTING;

int int_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size)
{
  return snprintf(payload, payload_max_size - 1, "{\"value\": %u}", (unsigned int)value);
}

int int100_to_mqtt_payload(uint16_t value, char *payload, int payload_max_size)
{
  return snprintf(payload, payload_max_size - 1, "{\"value\": %.2f}", (float)(value/100.0));
}

void my_connect_callback(struct mosquitto *mosq, void *obj, int rc) {
  struct mosq_config *cfg;
  int i, n;
  char topic[TOPIC_MAX_SIZE];

  assert(obj);
  cfg = (struct mosq_config *)obj;

  if (0 == rc) {
    status = STATUS_CONNACK_RECVD;
    // subscribe unit control set topics
    for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
      if (!unit_control_topics[i].set) {
        continue;
      }

      n = snprintf(topic, TOPIC_MAX_SIZE - 1, "%s/%s/%s/%s", cfg->id,
                   SET_TOPIC_PREFIX, UNIT_CONTROL_TOPIC_PREFIX,
                   unit_control_topics[i].name);
      if (n < 0 || n > (sizeof(topic) - 1)) {
        if (!cfg->quiet) {
          fprintf(stderr,
                  "can't generate topic for %s register(too long?). Ignored\n",
                  unit_control_topics[i].name);
        }
        continue;
      }

      mosquitto_subscribe(mosq, NULL, topic, cfg->qos);
    }
  } else {
    if (!cfg->quiet) {
      fprintf(stderr, "%s\n", mosquitto_connack_string(rc));
    }
  }
}

// void my_publish_callback(struct mosquitto *mosq, void *obj, int mid) {
//   struct mosq_config *cfg;

//   assert(obj);
//   cfg = (struct mosq_config *)obj;
// }

void my_subscribe_callback(struct mosquitto *mosq, void *obj, int mid,
                           int qos_count, const int *granted_qos) {
  struct mosq_config *cfg;
  int i;

  assert(obj);
  cfg = (struct mosq_config *)obj;

  if (!cfg->quiet) printf("Subscribed (mid: %d): %d", mid, granted_qos[0]);
  for (i = 1; i < qos_count; i++) {
    if (!cfg->quiet) printf(", %d", granted_qos[i]);
  }
  if (!cfg->quiet) printf("\n");
}

void my_message_callback(struct mosquitto *mosq, void *obj,
                         const struct mosquitto_message *message) {
  struct mosq_config *cfg;
  int i;
  char *topic_name;
  char *token;
  char *save_ptr;
  struct json_object *jobj, *field;

  assert(obj);
  cfg = (struct mosq_config *)obj;

  if (cfg->debug) {
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
  printf("token = %s\n", token);
  if (!token || (strncmp(cfg->id, token, strlen(cfg->id)) != 0)) {
    goto my_message_callback_end;
  }

  // match set
  token = strtok_r(0, "/", &save_ptr);
  printf("token = %s\n", token);
  if (!token ||
      (strncmp(SET_TOPIC_PREFIX, token, strlen(SET_TOPIC_PREFIX)) != 0)) {
    goto my_message_callback_end;
  }

  // match [unit-control]
  token = strtok_r(0, "/", &save_ptr);
  printf("token = %s\n", token);
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
          jobj = json_tokener_parse(message->payload);
          printf("jobj from str:\n---\n%s\n---\n",
                 json_object_to_json_string_ext(
                     jobj, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));
          if (json_object_object_get_ex(jobj, SET_TOPIC_VALUE_FIELD, &field)) {
            int value = json_object_get_int(field);
            printf("set %s to %d\n", unit_control_topics[i].name, value);
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
                                    struct mosq_config *cfg, uint16_t *regs) {
  int i, n;
  char topic[TOPIC_MAX_SIZE];
  char payload[PUBLISH_PAYLOAD_MAX_SIZE];

  // unit-control
  for (i = 0; i < UNIT_CONTROL_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic) - 1, "%s/%s/%s", cfg->id,
                 UNIT_CONTROL_TOPIC_PREFIX, unit_control_topics[i].name);
    if (n < 0 || n > (sizeof(topic) - 1)) {
      if (!cfg->quiet) {
        fprintf(stderr,
                "can't generate topic for %s register(too long?). Ignored\n",
                unit_control_topics[i].name);
      }
      continue;
    }
    if (!unit_control_topics[i].to_mqtt_payload) {
      continue;
    }
    n = unit_control_topics[i].to_mqtt_payload(regs[unit_control_topics[i].offset], payload, sizeof(payload));
    if (n < 0 || n > (sizeof(payload) - 1)) {
      if (!cfg->quiet) {
        fprintf(stderr,
                "can't generate payload for %s register(too long?). Ignored\n",
                unit_control_topics[i].name);
      }
      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, false);
  }
}

void publish_group_registers(struct mosquitto *mosq, struct mosq_config *cfg,
                             uint16_t *regs) {
  int i, n;
  char topic[TOPIC_MAX_SIZE];
  char payload[PUBLISH_PAYLOAD_MAX_SIZE];

  // group
  for (i = 0; i < GROUP_TOPICS_COUNT; i++) {
    n = snprintf(topic, sizeof(topic) - 1, "%s/%s/%s", cfg->id,
                 GROUP_TOPIC_PREFIX, group_topics[i].name);
    if (n < 0 || n > (sizeof(topic) - 1)) {
      if (!cfg->quiet) {
        fprintf(stderr,
                "can't generate topic for %s register(too long?). Ignored\n",
                group_topics[i].name);
      }
      continue;
    }
    if (!group_topics[i].to_mqtt_payload) {
      continue;
    }
    n = group_topics[i].to_mqtt_payload(regs[group_topics[i].offset], payload, sizeof(payload));
    if (n < 0 || n > (sizeof(payload) - 1)) {
      if (!cfg->quiet) {
        fprintf(stderr,
                "can't generate payload for %s register(too long?). Ignored\n",
                group_topics[i].name);
      }
      continue;
    }
    mosquitto_publish(mosq, NULL, topic, n, payload, 0, false);
  }
}

void print_usage(void) {
  int major, minor, revision;

  mosquitto_lib_version(&major, &minor, &revision);
  printf("rtdnet-mqtt-gateway is a RTD-NET to MQTT gateway.\n");
  printf("rtdnet-mqtt-gateway version %s running on libmosquitto %d.%d.%d.\n\n",
         VERSION, major, minor, revision);
  printf(
      "Usage: rtdnet-mqtt-gateway [-h host] [-k keepalive] [-p port] [-q qos] \n");
  printf("                     [-A bind_address]\n");
  printf("                     [-i id] [-I id_prefix]\n");
  printf("                     [-d] [--quiet]\n");
  printf("                     [-M max_inflight]\n");
  printf("                     [-u username [-P password]]\n");
  printf(
      "                     [--will-topic [--will-payload payload] [--will-qos "
      "qos] [--will-retain]]\n");
#ifdef WITH_TLS
  printf(
      "                     [{--cafile file | --capath dir} [--cert file] "
      "[--key file]\n");
  printf("                      [--ciphers ciphers] [--insecure]]\n");
#ifdef WITH_TLS_PSK
  printf(
      "                     [--psk hex-key --psk-identity identity [--ciphers "
      "ciphers]]\n");
#endif
#endif
  printf("       rtdnet-mqtt-gateway --help\n\n");
  printf(
      " -A : bind the outgoing socket to this host/ip address. Use to control "
      "which interface\n");
  printf("      the client communicates over.\n");
  printf(" -d : enable debug messages.\n");
  printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
  printf(
      " -i : id to use for this client. Defaults to rtdnet-mqtt-gateway_ "
      "appended with the process id.\n");
  printf(
      " -I : define the client id as id_prefix appended with the process id. "
      "Useful for when the\n");
  printf("      broker is using the clientid_prefixes option.\n");
  printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
  printf(" -M : the maximum inflight messages for QoS 1/2..\n");
  printf(" -p : network port to connect to. Defaults to 1883.\n");
  printf(" -P : provide a password (requires MQTT 3.1 broker)\n");
  printf(
      " -q : quality of service level to use for all messages. Defaults to "
      "0.\n");
  printf(" -u : provide a username (requires MQTT 3.1 broker)\n");
  printf(
      " -V : specify the version of the MQTT protocol to use when "
      "connecting.\n");
  printf("      Can be mqttv31 or mqttv311. Defaults to mqttv31.\n");
  printf(" --help : display this message.\n");
  printf(" --quiet : don't print error messages.\n");
  printf(
      " --will-payload : payload for the client Will, which is sent by the "
      "broker in case of\n");
  printf(
      "                  unexpected disconnection. If not given and will-topic "
      "is set, a zero\n");
  printf("                  length message will be sent.\n");
  printf(" --will-qos : QoS level for the client Will.\n");
  printf(" --will-retain : if given, make the client Will retained.\n");
  printf(" --will-topic : the topic on which to publish the client Will.\n");
#ifdef WITH_TLS
  printf(
      " --cafile : path to a file containing trusted CA certificates to enable "
      "encrypted\n");
  printf("            communication.\n");
  printf(
      " --capath : path to a directory containing trusted CA certificates to "
      "enable encrypted\n");
  printf("            communication.\n");
  printf(
      " --cert : client certificate for authentication, if required by "
      "server.\n");
  printf(
      " --key : client private key for authentication, if required by "
      "server.\n");
  printf(" --ciphers : openssl compatible list of TLS ciphers to support.\n");
  printf(
      " --tls-version : TLS protocol version, can be one of tlsv1.2 tlsv1.1 or "
      "tlsv1.\n");
  printf("                 Defaults to tlsv1.2 if available.\n");
  printf(
      " --insecure : do not check that the server certificate hostname matches "
      "the remote\n");
  printf(
      "              hostname. Using this option means that you cannot be sure "
      "that the\n");
  printf(
      "              remote host is the server you wish to connect to and so "
      "is insecure.\n");
  printf("              Do not use this option in a production environment.\n");
#ifdef WITH_TLS_PSK
  printf(
      " --psk : pre-shared-key in hexadecimal (no leading 0x) to enable "
      "TLS-PSK mode.\n");
  printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#endif
#endif
  printf("\nSee http://mosquitto.org/ for more information.\n\n");
}

int main(int argc, char *argv[]) {
  struct mosq_config cfg;
  struct mosquitto *mosq = NULL;
  int rc;
  struct timespec last_publish = {0}, now;

  rtdnet_t *ctx = NULL;
  uint16_t unit_control_regs[UNIT_CONTROL_REGISTERS_MAX] = {0};
  uint16_t group_regs1[GROUP_REGISTERS1_MAX] = {0};

  // TODO: add command line parameters
  ctx = rtdnet_new(SERVER_ADDRESS, "/dev/ttyUSB0", 9600, 'N', 8, 1);
  if (ctx == NULL) {
    fprintf(stderr, "Unable to allocate rtdnet context: %s\n",
            rtdnet_strerror(errno));
    return -1;
  }

  memset(&cfg, 0, sizeof(struct mosq_config));
  rc = client_config_load(&cfg, argc, argv);
  if (rc) {
    client_config_cleanup(&cfg);
    if (rc == 2) {
      /* --help */
      print_usage();
    } else {
      fprintf(stderr, "\nUse 'rtdnet-mqtt-gateway --help' to see usage.\n");
    }
    return 1;
  }

  mosquitto_lib_init();

  if (client_id_generate(&cfg, "rtdnet-mqtt-gw")) {
    return 1;
  }

  mosq = mosquitto_new(cfg.id, true, &cfg);
  if (!mosq) {
    switch (errno) {
      case ENOMEM:
        if (!cfg.quiet) fprintf(stderr, "Error: Out of memory.\n");
        break;
      case EINVAL:
        if (!cfg.quiet) fprintf(stderr, "Error: Invalid id.\n");
        break;
    }
    mosquitto_lib_cleanup();
    return 1;
  }

  if (client_opts_set(mosq, &cfg)) {
    return 1;
  }

  if (cfg.debug) {
    mosquitto_log_callback_set(mosq, my_log_callback);
    mosquitto_subscribe_callback_set(mosq, my_subscribe_callback);
  }

  mosquitto_connect_callback_set(mosq, my_connect_callback);
  //mosquitto_publish_callback_set(mosq, my_publish_callback);
  mosquitto_message_callback_set(mosq, my_message_callback);

  rc = client_connect(mosq, &cfg);
  if (rc) return rc;

  do {
    if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
      fprintf(stderr, "Error getting clock: %s\n", strerror(rc));
      return -1;
    }

    if (status == STATUS_CONNACK_RECVD &&
        ((now.tv_sec - last_publish.tv_sec) > 10)) {
      // get unit-control registers to publish them
      rc = rtdnet_read_unit_control_registers(ctx, unit_control_regs);
      if (rc != UNIT_CONTROL_REGISTERS_MAX) {
        fprintf(stderr, "Error reading unit control registers: %s\n",
                rtdnet_strerror(errno));
        return -1;
      }
      publish_unit_control_registers(mosq, &cfg, unit_control_regs);

      // get group registers to publish them
      rc = rtdnet_read_group_registers1(ctx, group_regs1);
      if (rc != GROUP_REGISTERS1_MAX) {
        fprintf(stderr, "Error reading group registers1: %s\n",
                rtdnet_strerror(errno));
        return -1;
      }
      publish_group_registers(mosq, &cfg, group_regs1);
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
