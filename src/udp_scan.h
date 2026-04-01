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
#define MIN_UDP_PACKET_HEADER_SIZE 8

/** Run the UDP scan based on the provided configuration */
int run_udp_scan(const Config *config);

/** Create a UDP socket for the given target address info */
int create_udp_socket(const struct addrinfo *target);

/** Resolve the target hostname into a list of address info structures for UDP scanning */
int resolve_udp_target(const Config *config, struct addrinfo **targets);

/** Send an empty UDP packet to the specified IPv4 destination address */
int send_udp_ipv4(int socket, const struct sockaddr_in *destination_address);

/** Send an empty UDP packet to the specified IPv6 destination address */
int send_udp_ipv6(int socket, const struct sockaddr_in6 *destination_address);

/** Capture ICMP responses for a sent UDP probe and determine port status */
int catch_icmp_response(pcap_t *pcap_handle, unsigned timeout_ms);

/** Scan UDP ports for a single target address and print results */
int scan_udp_ports_for_one_target(const Config *config, struct addrinfo *target);

#endif /* UDP_SCAN_H */
