#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>

#include "L4-scan.h"

bool has_selected_ports(const bool *ports) {
    if (ports == NULL) {
        return false;
    }

    for (int port = 1; port < MAX_PORTS; port++) {
        if (ports[port]) return true;
    }

    return false;
}

int ip_string_from_ipv4(const struct sockaddr_in *address, char *out, size_t out_size) {
    if (inet_ntop(AF_INET, &address->sin_addr, out, out_size) == NULL) {
        return ERROR;
    }
    return OK;
}

int ip_string_from_ipv6(const struct sockaddr_in6 *address, char *out, size_t out_size) {
    if (inet_ntop(AF_INET6, &address->sin6_addr, out, out_size) == NULL) {
        return ERROR;
    }
    return OK;
}

// Converts a generic socket address into printable IP text.
void ip_string_from_sockaddr(const struct sockaddr *addr, char *out, size_t out_size) {
    if (addr == NULL || out == NULL || out_size == 0) {
        return;
    }

    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *v4 = (const struct sockaddr_in *)addr;
        if (ip_string_from_ipv4(v4, out, out_size) == OK) return;
        snprintf(out, out_size, "<unknown>");
        return;
    }

    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)addr;
        if (ip_string_from_ipv6(v6, out, out_size) == OK) return;
        snprintf(out, out_size, "<unknown>");
        return;
    }

    snprintf(out, out_size, "<unknown>");
}

int set_target_port(struct sockaddr *addr, int port) {
    if (addr == NULL || port < 1 || port > 65535) {
        return ERROR;
    }

    if (addr->sa_family == AF_INET) {
        ((struct sockaddr_in *)addr)->sin_port = htons((in_port_t)port);
        return OK;
    }

    if (addr->sa_family == AF_INET6) {
        ((struct sockaddr_in6 *)addr)->sin6_port = htons((in_port_t)port);
        return OK;
    }

    return ERROR;
}

int bind_to_interface(int socket_fd, const char *interface_name) {
    if (socket_fd < 0 || interface_name == NULL) {
        return ERROR;
    }

    if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
                   interface_name, strlen(interface_name) + 1) < 0) {
        return ERROR;
    }

    return OK;
}