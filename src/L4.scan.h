// This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
// Author: Kristian Rucek > xrucekk00

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define DEFAULT_TIMEOUT_MS 1000
#define MAX_TIMEOUT_MS 3000
#define MAX_PORTS 65535

typedef enum{
  OK,
  ERROR,
  MALLOC_ERROR,
} Program_Status;

typedef enum{
    PROTOCOL_TCP,
    PROTOCOL_UDP,
} Protocol;

typedef enum{
    PORT_STATUS_OPEN,
    PORT_STATUS_CLOSED,
    PORT_STATUS_FILTERED,
} PortStatus;

typedef struct{
    const char *server_hostname;
    const char *port_string;
    bool tcp_ports[MAX_PORTS];
    bool udp_ports[MAX_PORTS];
    const char *interface_name;
    int timeout_ms;
} Config;

void print_help(void);

int interface(void);

int parse_ports(Config *config, bool *ports);

int tcp_ports(Config *config);

int udp_ports(Config *config);

int timeout(void);

int cli_argument_parsing(int argc, char *argv[], Config *config);