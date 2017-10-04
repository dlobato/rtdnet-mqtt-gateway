#ifndef GATEWAY_CONFIG_H
#define GATEWAY_CONFIG_H

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gateway_config {
  /* rtdnet */
  char* device;
  int baud;
  char parity;
  int data_bit; 
  int stop_bit;
	/* mqtt */
  char *id;
  int protocol_version;
  int keepalive;
  char *host;
  int port;
  int qos;
  bool retain;
  char *bind_address;
  bool debug;
  unsigned int max_inflight;
  char *username;
  char *password;
  char *will_topic;
  char *will_payload;
  long will_payloadlen;
  int will_qos;
  bool will_retain;
#ifdef WITH_TLS
  char *cafile;
  char *capath;
  char *certfile;
  char *keyfile;
  char *ciphers;
  bool insecure;
  char *tls_version;
#ifdef WITH_TLS_PSK
  char *psk;
  char *psk_identity;
#endif
#endif
};

int gateway_config_load(struct gateway_config *config, int argc, char *argv[]);
void gateway_config_cleanup(struct gateway_config *cfg);
void gateway_config_usage(void);

#ifdef __cplusplus
}
#endif

#endif
