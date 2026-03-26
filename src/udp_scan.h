/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */

#ifndef UDP_SCAN_H
#define UDP_SCAN_H

#include <netinet/in.h>
#include "netinet/ip6.h"
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "addr_helpers.h"
#include "L4-scan.h"
#include "tcp_scan.h"

#define ICMP_TYPE 3
#define ICMP_CODE 3
#define ICMP6_TYPE 1
#define ICMP6_CODE 4

int run_udp_scan(const Config *config);

int create_udp_socket(const struct addrinfo *target);

int resolve_udp_target(const Config *config, struct addrinfo **targets);

int send_udp_ipv4(int socket, const struct sockaddr_in *destination_address);

int send_udp_ipv6(int socket, const struct sockaddr_in6 *destination_address);

int catch_icmp_response(pcap_t *pcap_handle, unsigned timeout_ms);

int scan_udp_ports_for_one_target(const Config *config, struct addrinfo *target);

#endif /* UDP_SCAN_H */
