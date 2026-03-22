// udp_scan.c - Implements UDP scan 
// Author: Kristian Rucek > xrucekk00

#include "L4-scan.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "L4-scan.h"
#include "udp_scan.h"
#include "addr_helpers.h"


// static const char *udp_status_to_text(Port_status status) {
//     if (status == PORT_STATUS_OPEN) return "open";
//     if (status == PORT_STATUS_CLOSED) return "closed";
//     return "open";
// }

// static int create_udp_socket(const struct addrinfo *target) {
//     return socket(target->ai_family, target->ai_socktype, target->ai_protocol);
// }

uint16_t udp_checksum_ipv4(struct in_addr source_ip, struct in_addr destination_ip, Udp_header *udp_header) {
    return checksum_ipv4(source_ip, destination_ip, IPPROTO_UDP, udp_header, sizeof(Udp_header));
}



int run_udp_scan(const Config *config) {
    //  struct addrinfo *targets = NULL;
    // if (resolve_udp_targets(config, &targets) != UDP_SCAN_OK) {
    //     return ERROR;
    // }

    // for (struct addrinfo *target = targets; target != NULL; target = target->ai_next) {
    //     scan_udp_ports_for_one_target(config, target);
    // }

    printf("UDP scan is not implemented yet. %s\n", config->server_hostname);
    // freeaddrinfo(targets);
    return OK;
}
