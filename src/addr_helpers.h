#ifndef ADDR_HELLPERS_H
#define ADDR_HELLPERS_H


bool has_selected_ports(const bool *ports);

int ip_string_from_ipv4(const struct sockaddr_in *address, char *out, size_t out_size);

int ip_string_from_ipv6(const struct sockaddr_in6 *address, char *out, size_t out_size);

void ip_string_from_sockaddr(const struct sockaddr *addr, char *out, size_t out_size);

int resolve_tcp_targets(const Config *config, struct addrinfo **targets);

int set_target_port(struct sockaddr *addr, int port);

int bind_to_interface(int socket_fd, const char *interface_name);


#endif // ADDR_HELLPERS_H