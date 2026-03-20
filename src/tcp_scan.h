#ifndef TCP_SCAN_H
#define TCP_SCAN_H

#include "L4-scan.h"
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>

/** TCP header structure for raw packet construction (RFC 793) */
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

#define IP_VERSION_IHL(header_bytes) ((4 << 4) | ((header_bytes) / 4))
#define TCP_DATA_OFFSET(header_bytes) (((header_bytes) / 4) << 4)

/* libpcap link layer header lengths for different interface types */
#define PCAP_LINK_HEADER_ETHERNET 14    /* DLT_EN10MB (Ethernet, default) */
#define PCAP_LINK_HEADER_LINUX_SLL 16   /* DLT_LINUX_SLL (Cooked packet, tcpdump format) */
#define PCAP_LINK_HEADER_LOOPBACK 4     /* DLT_NULL (Loopback interface) */


/** Get the local IP address for a specific network interface */
int get_local_ip_address(const char *interface_name, struct in_addr *local_ip);

/** Send a raw TCP SYN packet to the target */
int send_tcp_syn(int raw_socket, const struct sockaddr_in *destination_address, Ip_header *ip_header, Tcp_header *tcp_header);

/** Calculate TCP checksum with pseudo-header (RFC 793) */
uint16_t tcp_checksum(struct in_addr source_ip, struct in_addr destination_ip, Tcp_header *tcp_header);

/** Main TCP scanning function for all targets */
int run_tcp_scan(const Config *config);

/** Resolve hostname to IP address(es) using getaddrinfo */
int resolve_tcp_targets(const Config *config, struct addrinfo **targets);

/** Scan TCP ports for a single target IP address */
int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target);

#endif /* TCP_SCAN_H */