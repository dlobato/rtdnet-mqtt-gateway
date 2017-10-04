#include "mosquitto_helper.h"
#include <errno.h>
#include <string.h>

int client_opts_set(struct mosquitto *mosq, struct gateway_config *cfg) {
  if (cfg->will_topic &&
      mosquitto_will_set(mosq, cfg->will_topic, cfg->will_payloadlen,
                         cfg->will_payload, cfg->will_qos, cfg->will_retain)) {
    fprintf(stderr, "Error: Problem setting will.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
  if (cfg->username &&
      mosquitto_username_pw_set(mosq, cfg->username, cfg->password)) {
    fprintf(stderr, "Error: Problem setting username and password.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
#ifdef WITH_TLS
  if ((cfg->cafile || cfg->capath) &&
      mosquitto_tls_set(mosq, cfg->cafile, cfg->capath, cfg->certfile,
                        cfg->keyfile, NULL)) {
    fprintf(stderr, "Error: Problem setting TLS options.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
  if (cfg->insecure && mosquitto_tls_insecure_set(mosq, true)) {
    fprintf(stderr, "Error: Problem setting TLS insecure option.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
#ifdef WITH_TLS_PSK
  if (cfg->psk &&
      mosquitto_tls_psk_set(mosq, cfg->psk, cfg->psk_identity, NULL)) {
    fprintf(stderr, "Error: Problem setting TLS-PSK options.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
#endif
  if ((cfg->tls_version || cfg->ciphers) &&
      mosquitto_tls_opts_set(mosq, 1, cfg->tls_version, cfg->ciphers)) {
    fprintf(stderr, "Error: Problem setting TLS options.\n");
    mosquitto_lib_cleanup();
    return 1;
  }
#endif
  mosquitto_max_inflight_messages_set(mosq, cfg->max_inflight);
  mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &(cfg->protocol_version));
  return 0;
}

int client_connect(struct mosquitto *mosq, struct gateway_config *cfg) {
  char err[1024];
  int rc;

  rc = mosquitto_connect_bind(mosq, cfg->host, cfg->port, cfg->keepalive,
                              cfg->bind_address);
  if (rc > 0) {
    if (rc == MOSQ_ERR_ERRNO) {
      strerror_r(errno, err, 1024);
      fprintf(stderr, "Error: %s\n", err);
    } else {
      fprintf(stderr, "Unable to connect (%s).\n", mosquitto_strerror(rc));
    }

    mosquitto_lib_cleanup();
    return rc;
  }
  return 0;
}
