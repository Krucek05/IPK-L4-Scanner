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


int run_udp_scan(const Config *config);

#endif /* UDP_SCAN_H */
