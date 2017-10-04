#ifndef MOSQUITTO_HELPER_H
#define MOSQUITTO_HELPER_H

#include <stdint.h>
#include <mosquitto.h>
#include "gateway_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int client_opts_set(struct mosquitto *mosq, struct gateway_config *cfg);
int client_connect(struct mosquitto *mosq, struct gateway_config *cfg);

#ifdef __cplusplus
}
#endif

#endif  // MOSQUITTO_H