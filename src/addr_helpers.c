#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdbool.h>

#include "L4-scan.h"

#define CHECKSUM_WORD_SIZE_BYTES 2
#define CHECKSUM_SINGLE_BYTE_REMAINDER 1
#define CHECKSUM_CARRY_SHIFT 16
#define CHECKSUM_LOW_16_MASK 0xFFFF

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

// check if packet was not corrupted 
// Checksum calculation adapted from https://tools.ietf.org/html/rfc1071 and AI suggestions, but implemented for my usage
uint16_t checksum(const void *data, size_t length) {
    uint32_t sum = 0;
    const uint16_t *ptr = data;

    while (length > CHECKSUM_SINGLE_BYTE_REMAINDER) {
        sum += *ptr++;
        length -= CHECKSUM_WORD_SIZE_BYTES;
    }

    if (length > 0) {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> CHECKSUM_CARRY_SHIFT) {
        sum = (sum & CHECKSUM_LOW_16_MASK) + (sum >> CHECKSUM_CARRY_SHIFT);
    }
    return (uint16_t)(~sum);
}

uint16_t checksum_ipv4(struct in_addr source_ip, struct in_addr destination_ip,
    uint8_t protocol, const void *header, size_t header_length) {

    if (header == NULL || header_length == 0) {
        return 0;
    }

    struct {
        uint32_t source;
        uint32_t destination;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } pseudo_header;

    pseudo_header.source = source_ip.s_addr;
    pseudo_header.destination = destination_ip.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.protocol = protocol;
    pseudo_header.length = htons((uint16_t)header_length);

    uint8_t buffer[sizeof(pseudo_header) + header_length];
    memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), header, header_length);

    return checksum(buffer, sizeof(buffer));
}