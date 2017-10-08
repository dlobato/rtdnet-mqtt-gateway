#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mosquitto.h>
#include "gateway_config.h"

static int gateway_config_line_proc(struct gateway_config *cfg, int argc,
                                    char *argv[]);

void init_config(struct gateway_config *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->server_addr = 0;
  cfg->baud = 9600;
  cfg->parity = 'N';
  cfg->data_bit = 8;
  cfg->stop_bit = 1;
  cfg->port = 1883;
  cfg->max_inflight = 20;
  cfg->keepalive = 60;
  cfg->protocol_version = MQTT_PROTOCOL_V31;
  cfg->publish_delay_s = 60;
}

void gateway_config_cleanup(struct gateway_config *cfg) {
  free(cfg->device);
  free(cfg->id);
  free(cfg->host);
  free(cfg->bind_address);
  free(cfg->username);
  free(cfg->password);
  free(cfg->will_topic);
  free(cfg->will_payload);
#ifdef WITH_TLS
  free(cfg->cafile);
  free(cfg->capath);
  free(cfg->certfile);
  free(cfg->keyfile);
  free(cfg->ciphers);
  free(cfg->tls_version);
#ifdef WITH_TLS_PSK
  free(cfg->psk);
  free(cfg->psk_identity);
#endif
#endif
}

int gateway_config_load(struct gateway_config *cfg, int argc, char *argv[]) {
  int rc;

  init_config(cfg);

  /* Deal with real argc/argv */
  rc = gateway_config_line_proc(cfg, argc, argv);
  if (rc) return rc;

  if (cfg->will_payload && !cfg->will_topic) {
    fprintf(stderr, "Error: Will payload given, but no will topic given.\n");
    return 1;
  }
  if (cfg->will_retain && !cfg->will_topic) {
    fprintf(stderr, "Error: Will retain given, but no will topic given.\n");
    return 1;
  }
  if (cfg->password && !cfg->username) {
    fprintf(stderr, "Warning: Not using password since username not set.\n");
  }
#ifdef WITH_TLS
  if ((cfg->certfile && !cfg->keyfile) || (cfg->keyfile && !cfg->certfile)) {
    fprintf(stderr,
            "Error: Both certfile and keyfile must be provided if one of them "
            "is.\n");
    return 1;
  }
#endif
#ifdef WITH_TLS_PSK
  if ((cfg->cafile || cfg->capath) && cfg->psk) {
    fprintf(stderr,
            "Error: Only one of --psk or --cafile/--capath may be used at "
            "once.\n");
    return 1;
  }
  if (cfg->psk && !cfg->psk_identity) {
    fprintf(stderr, "Error: --psk-identity required if --psk used.\n");
    return 1;
  }
#endif
  if (cfg->server_addr == 0) {
    fprintf(stderr, "Error: --server-address required.\n");
    return 1;
  }

  if (!cfg->device) {
    fprintf(stderr, "Error: --device required.\n");
    return 1;
  }

  if (!cfg->id) {
    fprintf(stderr, "Error: -i required.\n");
    return 1;
  }

  if (!cfg->host) {
    cfg->host = "localhost";
  }
  return 0;
}

/* Process a tokenised single line from a file or set of real argc/argv */
int gateway_config_line_proc(struct gateway_config *cfg, int argc,
                             char *argv[]) {
  int i;

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
      if (i == argc - 1) {
        fprintf(stderr, "Error: -p argument given but no port specified.\n\n");
        return 1;
      } else {
        cfg->port = atoi(argv[i + 1]);
        if (cfg->port < 1 || cfg->port > 65535) {
          fprintf(stderr, "Error: Invalid port given: %d\n", cfg->port);
          return 1;
        }
      }
      i++;
    } else if (!strcmp(argv[i], "-A")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: -A argument given but no address specified.\n\n");
        return 1;
      } else {
        cfg->bind_address = strdup(argv[i + 1]);
      }
      i++;
#ifdef WITH_TLS
    } else if (!strcmp(argv[i], "--cafile")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --cafile argument given but no file specified.\n\n");
        return 1;
      } else {
        cfg->cafile = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--capath")) {
      if (i == argc - 1) {
        fprintf(
            stderr,
            "Error: --capath argument given but no directory specified.\n\n");
        return 1;
      } else {
        cfg->capath = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--cert")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --cert argument given but no file specified.\n\n");
        return 1;
      } else {
        cfg->certfile = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--ciphers")) {
      if (i == argc - 1) {
        fprintf(
            stderr,
            "Error: --ciphers argument given but no ciphers specified.\n\n");
        return 1;
      } else {
        cfg->ciphers = strdup(argv[i + 1]);
      }
      i++;
#endif
    } else if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--debug")) {
      cfg->debug = true;
    } else if (!strcmp(argv[i], "--help")) {
      return 2;
    } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--host")) {
      if (i == argc - 1) {
        fprintf(stderr, "Error: -h argument given but no host specified.\n\n");
        return 1;
      } else {
        cfg->host = strdup(argv[i + 1]);
      }
      i++;
#ifdef WITH_TLS
    } else if (!strcmp(argv[i], "--insecure")) {
      cfg->insecure = true;
#endif
    } else if (!strcmp(argv[i], "-i") || !strcmp(argv[i], "--id")) {
      if (i == argc - 1) {
        fprintf(stderr, "Error: -i argument given but no id specified.\n\n");
        return 1;
      } else {
        cfg->id = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "-k") || !strcmp(argv[i], "--keepalive")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: -k argument given but no keepalive specified.\n\n");
        return 1;
      } else {
        cfg->keepalive = atoi(argv[i + 1]);
        if (cfg->keepalive > 65535) {
          fprintf(stderr, "Error: Invalid keepalive given: %d\n",
                  cfg->keepalive);
          return 1;
        }
      }
      i++;
#ifdef WITH_TLS
    } else if (!strcmp(argv[i], "--key")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --key argument given but no file specified.\n\n");
        return 1;
      } else {
        cfg->keyfile = strdup(argv[i + 1]);
      }
      i++;
#endif
    } else if (!strcmp(argv[i], "-M")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: -M argument given but max_inflight not specified.\n\n");
        return 1;
      } else {
        cfg->max_inflight = atoi(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "-V") ||
               !strcmp(argv[i], "--protocol-version")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --protocol-version argument given but no version "
                "specified.\n\n");
        return 1;
      } else {
        if (!strcmp(argv[i + 1], "mqttv31")) {
          cfg->protocol_version = MQTT_PROTOCOL_V31;
        } else if (!strcmp(argv[i + 1], "mqttv311")) {
          cfg->protocol_version = MQTT_PROTOCOL_V311;
        } else {
          fprintf(stderr,
                  "Error: Invalid protocol version argument given.\n\n");
          return 1;
        }
        i++;
      }
#ifdef WITH_TLS_PSK
    } else if (!strcmp(argv[i], "--psk")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --psk argument given but no key specified.\n\n");
        return 1;
      } else {
        cfg->psk = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--psk-identity")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --psk-identity argument given but no identity "
                "specified.\n\n");
        return 1;
      } else {
        cfg->psk_identity = strdup(argv[i + 1]);
      }
      i++;
#endif
    } else if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--qos")) {
      if (i == argc - 1) {
        fprintf(stderr, "Error: -q argument given but no QoS specified.\n\n");
        return 1;
      } else {
        cfg->qos = atoi(argv[i + 1]);
        if (cfg->qos < 0 || cfg->qos > 2) {
          fprintf(stderr, "Error: Invalid QoS given: %d\n", cfg->qos);
          return 1;
        }
      }
      i++;
#ifdef WITH_TLS
    } else if (!strcmp(argv[i], "--tls-version")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --tls-version argument given but no version "
                "specified.\n\n");
        return 1;
      } else {
        cfg->tls_version = strdup(argv[i + 1]);
      }
      i++;
#endif
    } else if (!strcmp(argv[i], "-u") || !strcmp(argv[i], "--username")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: -u argument given but no username specified.\n\n");
        return 1;
      } else {
        cfg->username = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "-P") || !strcmp(argv[i], "--pw")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: -P argument given but no password specified.\n\n");
        return 1;
      } else {
        cfg->password = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--will-payload")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --will-payload argument given but no will payload "
                "specified.\n\n");
        return 1;
      } else {
        cfg->will_payload = strdup(argv[i + 1]);
        cfg->will_payloadlen = strlen(cfg->will_payload);
      }
      i++;
    } else if (!strcmp(argv[i], "--will-qos")) {
      if (i == argc - 1) {
        fprintf(
            stderr,
            "Error: --will-qos argument given but no will QoS specified.\n\n");
        return 1;
      } else {
        cfg->will_qos = atoi(argv[i + 1]);
        if (cfg->will_qos < 0 || cfg->will_qos > 2) {
          fprintf(stderr, "Error: Invalid will QoS %d.\n\n", cfg->will_qos);
          return 1;
        }
      }
      i++;
    } else if (!strcmp(argv[i], "--will-retain")) {
      cfg->will_retain = true;
    } else if (!strcmp(argv[i], "--will-topic")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --will-topic argument given but no will topic "
                "specified.\n\n");
        return 1;
      } else {
        if (mosquitto_pub_topic_check(argv[i + 1]) == MOSQ_ERR_INVAL) {
          fprintf(
              stderr,
              "Error: Invalid will topic '%s', does it contain '+' or '#'?\n",
              argv[i + 1]);
          return 1;
        }
        cfg->will_topic = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--device")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --device argument given but no serial device "
                "specified.\n\n");
        return 1;
      } else {
        cfg->device = strdup(argv[i + 1]);
      }
      i++;
    } else if (!strcmp(argv[i], "--server-address")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --server-address argument given but no address "
                "specified.\n\n");
        return 1;
      } else {
        cfg->server_addr = atoi(argv[i + 1]);
        if (cfg->server_addr < 0 || cfg->server_addr > 63) {
          fprintf(stderr, "Error: Invalid server address %d.\n\n",
                  cfg->server_addr);
          return 1;
        }
      }
      i++;
    } else if (!strcmp(argv[i], "--publish-delay")) {
      if (i == argc - 1) {
        fprintf(stderr,
                "Error: --publish-delay argument given but no delay "
                "specified.\n\n");
        return 1;
      } else {
        cfg->publish_delay_s = atoi(argv[i + 1]);
        if (cfg->publish_delay_s < 0) {
          fprintf(stderr, "Error: Invalid publish delay %d.\n\n",
                  cfg->server_addr);
          return 1;
        }
      }
      i++;
    } else {
      goto unknown_option;
    }
  }

  return 0;

unknown_option:
  fprintf(stderr, "Error: Unknown option '%s'.\n", argv[i]);
  return 1;
}

// clang-format off
void gateway_config_usage(void) {
  int major, minor, revision;

  mosquitto_lib_version(&major, &minor, &revision);
  printf("rtdnet-mqtt-gateway is a RTD-NET to MQTT gateway.\n");
  printf("rtdnet-mqtt-gateway version %s running on libmosquitto %d.%d.%d.\n\n",
         VERSION, major, minor, revision);
  printf("Usage: rtdnet-mqtt-gateway [-h host] [-k keepalive] [-p port] [-q qos]\n");
  printf("                     [-A bind_address]\n");
  printf("                     [-i id]\n");
  printf("                     [-d]\n");
  printf("                     [-M max_inflight]\n");
  printf("                     [-u username [-P password]]\n");
  printf("                     [--server-address address]\n");
  printf("                     [--device device]\n");
  printf("                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]\n");
#ifdef WITH_TLS
  printf("                     [{--cafile file | --capath dir} [--cert file] [--key file]\n");
  printf("                     [--ciphers ciphers] [--insecure]]\n");
#ifdef WITH_TLS_PSK
  printf("                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]\n");
#endif
#endif
  printf("       rtdnet-mqtt-gateway --help\n\n");
  printf(" -A : bind the outgoing socket to this host/ip address. Use to control which interface\n");
  printf("      the client communicates over.\n");
  printf(" -d : enable debug messages.\n");
  printf(" -h : mqtt host to connect to. Defaults to localhost.\n");
  printf(" -i : id to use for this client. Defaults to random id.\n");
  printf(" -k : keep alive in seconds for this client. Defaults to 60.\n");
  printf(" -M : the maximum inflight messages for QoS 1/2..\n");
  printf(" -p : network port to connect to. Defaults to 1883.\n");
  printf(" -P : provide a password (requires MQTT 3.1 broker)\n");
  printf(" -q : quality of service level to use for all messages. Defaults to 0.\n");
  printf(" -u : provide a username (requires MQTT 3.1 broker)\n");
  printf(" -V : specify the version of the MQTT protocol to use when connecting.\n");
  printf("      Can be mqttv31 or mqttv311. Defaults to mqttv31.\n");
  printf(" --help : display this message.\n");
  printf(" --server-address : modbus address for server device [0-63].\n");
  printf(" --device device : serial port device.\n");
  printf(" --will-payload : payload for the client Will, which is sent by the broker in case of\n");
  printf("                  unexpected disconnection. If not given and will-topic is set, a zero\n");
  printf("                  length message will be sent.\n");
  printf(" --will-qos : QoS level for the client Will.\n");
  printf(" --will-retain : if given, make the client Will retained.\n");
  printf(" --will-topic : the topic on which to publish the client Will.\n");
#ifdef WITH_TLS
  printf(" --cafile : path to a file containing trusted CA certificates to enable encrypted\n");
  printf("            communication.\n");
  printf(" --capath : path to a directory containing trusted CA certificates to enable encrypted\n");
  printf("            communication.\n");
  printf(" --cert : client certificate for authentication, if required by server.\n");
  printf(" --key : client private key for authentication, if required by server.\n");
  printf(" --ciphers : openssl compatible list of TLS ciphers to support.\n");
  printf(" --tls-version : TLS protocol version, can be one of tlsv1.2 tlsv1.1 or tlsv1.\n");
  printf("                 Defaults to tlsv1.2 if available.\n");
  printf(" --insecure : do not check that the server certificate hostname matches the remote\n");
  printf("              hostname. Using this option means that you cannot be sure that the\n");
  printf("              remote host is the server you wish to connect to and so is insecure.\n");
  printf("              Do not use this option in a production environment.\n");
#ifdef WITH_TLS_PSK
  printf(" --psk : pre-shared-key in hexadecimal (no leading 0x) to enable TLS-PSK mode.\n");
  printf(" --psk-identity : client identity string for TLS-PSK mode.\n");
#endif
#endif
  printf(" --publish-delay delay : delay in seconds between rtdnet status updates.\n");
  printf("\nSee http://mosquitto.org/ for more information.\n\n");
}
// clang-format on