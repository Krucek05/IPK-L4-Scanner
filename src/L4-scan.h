#ifndef L4_SCAN_H
#define L4_SCAN_H

// This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
// Author: Kristian Rucek > xrucekk00

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <stdbool.h>

#define DEFAULT_TIMEOUT_MS 1000
#define MAX_TIMEOUT_MS 3000
#define MAX_PORTS 65536
#define MY_RANDOM_PORT 54321
#define SEQ_NUM 123456789

typedef enum{
  OK,
  ERROR = -1 ,
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
} Port_status;

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

bool has_selected_ports(const bool *ports);

int run_tcp_scan(const Config *config);
int run_udp_scan(const Config *config);

#endif // L4_SCAN_H