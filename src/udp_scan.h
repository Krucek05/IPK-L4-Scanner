// udp_scan.h - Header for UDP scanning functions
// Author: Kristian Rucek > xrucekk00

#ifndef UDP_SCAN_H
#define UDP_SCAN_H

#include "L4-scan.h"
#include "addr_helpers.h"
#include <netinet/in.h>
#include <string.h>


typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} Udp_header;

uint16_t udp_checksum_ipv4(struct in_addr source_ip, struct in_addr destination_ip, Udp_header *udp_header);
uint16_t udp_checksum_ipv6(struct in6_addr source_ip, struct in6_addr destination_ip, Udp_header *udp_header);

int run_udp_scan(const Config *config);

#endif /* UDP_SCAN_H */
