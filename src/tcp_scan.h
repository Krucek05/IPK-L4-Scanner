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
    uint16_t destination_port;
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
    struct in_addr destination_ip;
} Ipv4_header;

typedef struct {
    uint32_t version_traffic_class_flow_label; // Version (4 bits) + Traffic Class (8 bits) + Flow Label (20 bits)
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr source_ip;
    struct in6_addr destination_ip;
} Ipv6_header;

#define IPV4_VERSION_IHL(header_bytes) ((4 << 4) | ((header_bytes) / 4))
#define TCP_DATA_OFFSET(header_bytes) (((header_bytes) / 4) << 4)

/* libpcap link layer header lengths for different interface types */
#define PCAP_LINK_HEADER_ETHERNET 14    /* DLT_EN10MB (Ethernet, default) */
#define PCAP_LINK_HEADER_LINUX_SLL 16   /* DLT_LINUX_SLL (Cooked packet, tcpdump format) */
#define PCAP_LINK_HEADER_LOOPBACK 4     /* DLT_NULL (Loopback interface) */

#define DEFAULT_IP_TTL 64
#define DEFAULT_IPV6_HOP_LIMIT 64
#define TCP_FLAG_SYN 0x02
#define IPV6_PSEUDO_HEADER_ZERO_BYTES 3

#define IP_VERSION_MASK 0x0F
#define IPV4_VERSION_VALUE 4
#define IPV6_VERSION_VALUE 6
#define IP_VERSION_FROM_FIRST_BYTE(first_byte) (((first_byte) >> 4) & IP_VERSION_MASK)
#define IS_IPV4_VERSION(version) ((version) == IPV4_VERSION_VALUE)
#define IS_IPV6_VERSION(version) ((version) == IPV6_VERSION_VALUE)

#define TCP_PCAP_FILTER_MAX_LENGTH (INET6_ADDRSTRLEN + 32)


/** Get the local IP address for a specific network interface */
int get_local_ip_address(const char *interface_name, int family, void *local_ip);

/** Send a raw TCP SYN packet to the target */
int send_tcp_syn_ipv4(int raw_socket, const struct sockaddr_in *destination_address, Ipv4_header *ip_header, Tcp_header *tcp_header);

/** Send a raw TCP SYN packet to IPv6 target */
int send_tcp_syn_ipv6(int raw_socket, const struct sockaddr_in6 *destination_address, Tcp_header *tcp_header);

int get_link_header_length(int link_type);

/** Main TCP scanning function for all targets */
int run_tcp_scan(const Config *config);

/** Resolve hostname to IP address(es) using getaddrinfo */
int resolve_tcp_targets(const Config *config, struct addrinfo **targets);

pcap_t *initialize_pcap_listener(const Config *config, struct addrinfo *target);

/** Scan TCP ports for a single target IP address */
int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target);

#endif /* TCP_SCAN_H */