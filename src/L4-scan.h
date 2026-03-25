/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */


#ifndef L4_SCAN_H
#define L4_SCAN_H

#include <arpa/inet.h>
#include <sysexits.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <stdbool.h>

#define MAX_PROCESSED_SCANNS 2
#define DEFAULT_TIMEOUT_MS 1000
#define MAX_TIMEOUT_MS 3000
#define MAX_PORT_NUMBER 65535
#define MIN_PORT_NUMBER 1
#define MAX_PORTS 65536
#define MY_RANDOM_PORT 54321
#define SEQ_NUM 123456789
#define SLIDING_WINDOW_SIZE 65535
#define PORT_ERROR -1


typedef enum{
    ERROR = -1 ,
    MALLOC_ERROR,
} Program_Status;

typedef enum {SCAN_NONE, SCAN_TCP, SCAN_UDP } ScanType;

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
    unsigned timeout_ms;
    bool exit_after_print;
    ScanType order_of_scanning[MAX_PROCESSED_SCANNS]; // Stores which flag was seen 1st and 2nd
} Config;

/* Command-line parsing and main functions */

/** Print usage help and exit information */
void print_help(Config *config);

/** Parse command-line arguments into Config structure */
int cli_argument_parsing(int argc, char *argv[], Config *config);

/** Parse a single port string into integer value */
int parse_single_port(const char *str);

/** Parse comma/range port expression into selected ports array */
int parse_ports(Config *config, bool *ports);

long calculate_elapsed_ms(struct timeval start_time);

/* Scanning functions */

/** Run TCP port scanning for configured targets and ports */
int run_tcp_scan(const Config *config);

/** Run UDP port scanning for configured targets and ports */
int run_udp_scan(const Config *config);

#endif /* L4_SCAN_H */