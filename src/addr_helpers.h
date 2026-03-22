#ifndef ADDR_HELPERS_H
#define ADDR_HELPERS_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>

#define CHECKSUM_WORD_SIZE_BYTES 2
#define CHECKSUM_SINGLE_BYTE_REMAINDER 1
#define CHECKSUM_CARRY_SHIFT 16
#define CHECKSUM_LOW_16_MASK 0xFFFF

/** Check if any TCP or UDP ports are selected in the boolean array */
bool has_selected_ports(const bool *ports);

/** Convert IPv4 socket address to human-readable IP string */
int ip_string_from_ipv4(const struct sockaddr_in *address, char *out, size_t out_size);

/** Convert IPv6 socket address to human-readable IP string */
int ip_string_from_ipv6(const struct sockaddr_in6 *address, char *out, size_t out_size);

/** Convert any socket address (IPv4/IPv6) to human-readable IP string */
void ip_string_from_sockaddr(const struct sockaddr *addr, char *out, size_t out_size);

/** Set the port number on a socket address (IPv4/IPv6 compatible) */
int set_target_port(struct sockaddr *addr, int port);

/** Bind a socket to a specific network interface */
int bind_to_interface(int socket_fd, const char *interface_name);

/** Configure a raw socket for user-crafted IP packets and optional interface binding */
int configure_raw_socket(int raw_socket, int family, const char *interface_name);

/** RFC1071 checksum over arbitrary bytes */
uint16_t checksum(const void *data, size_t length);

/** RFC1071 checksum over IPv4 pseudo-header + L4 header bytes */
uint16_t checksum_ipv4(struct in_addr source_ip, struct in_addr destination_ip,
	uint8_t protocol, const void *header, size_t header_length);

/** RFC1071 checksum over IPv6 pseudo-header + L4 header bytes */
uint16_t checksum_ipv6(struct in6_addr source_ip, struct in6_addr destination_ip,
	uint8_t next_header, const void *header, size_t header_length);

#endif /* ADDR_HELPERS_H */