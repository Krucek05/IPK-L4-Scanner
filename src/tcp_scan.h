#ifndef TCP_SCAN_H
#define TCP_SCAN_H

#include "L4-scan.h"

typedef struct  {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset; // 4 bits
    uint8_t flags;       // 6 bits
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} Tcp_header;

typedef struct  {
    uint8_t version_ihl; // Version (4 bits) + IHL (4 bits)
    uint8_t dscp_ecn;   // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    struct in_addr source_ip;
    struct in_addr dest_ip;
} Ip_header;


int get_local_ip_address(const char *interface_name, struct in_addr *local_ip);

int send_tcp_syn(int raw_socket, const struct sockaddr_in *destination_address, Ip_header *ip_header, Tcp_header *tcp_header);

uint16_t tcp_checksum(struct in_addr source_ip, struct in_addr destination_ip, Tcp_header *tcp_header);

int run_tcp_scan(const Config *config);

int resolve_tcp_targets(const Config *config, struct addrinfo **targets);

int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target);






#endif // TCP_SCAN_H





