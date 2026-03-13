// This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
// Author: Kristian Rucek > xrucekk00

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

#include <arpa/inet.h>
#include <netdb.h>

#define DEFAULT_TIMEOUT_MS 1000
#define MAX_PORTS 65536

typedef enum{
  OK,
  ERROR = -1,
  MALLOC_ERROR,
} Program_status;

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

typedef struct{
    char* Ip_adresses;
} Scanned_connection;

void print_help(void);

int interface(void);

int parse_ports(Config *config, bool *ports);

int cli_argument_parsing(int argc, char *argv[], Config *config);

int run_tcp_scan(const Config *config);
int run_udp_scan(const Config *config);

bool has_selected_ports(const bool *ports);
void ip_string_from_sockaddr(const struct sockaddr *addr, char *out, size_t out_size);
int set_target_port(struct sockaddr *addr, int port);
int bind_to_interface(int socket_fd, const char *interface_name);