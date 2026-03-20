#ifndef ADDR_HELPERS_H
#define ADDR_HELPERS_H

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stddef.h>

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

#endif /* ADDR_HELPERS_H */