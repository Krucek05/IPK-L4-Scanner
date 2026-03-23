// udp_scan.c - Implements UDP scan 
// Author: Kristian Rucek > xrucekk00



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

// uint16_t udp_checksum_ipv4(struct in_addr source_ip, struct in_addr destination_ip, Udp_header *udp_header) {
//     return checksum_ipv4(source_ip, destination_ip, IPPROTO_UDP, udp_header, sizeof(Udp_header));
// }

// uint16_t udp_checksum_ipv6(struct in6_addr source_ip, struct in6_addr destination_ip, Udp_header *udp_header) {
//     return checksum_ipv6(source_ip, destination_ip, IPPROTO_UDP, udp_header, sizeof(Udp_header));
// }


int create_udp_socket(const struct addrinfo *target) {
    int probe_socket =  socket(target->ai_family, target->ai_socktype, target->ai_protocol);
    if (probe_socket < 0) {
        fprintf(stderr,"socket\n");
        return ERROR;
    }

    return OK;
}

int resolve_udp_target(const Config *config, struct addrinfo **targets) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6.
    hints.ai_socktype = SOCK_DGRAM;

    if(getaddrinfo(config->server_hostname, NULL, &hints, targets) != 0) {
        fprintf(stderr,"getaddrinfo\n");
        return ERROR;
    }
    return OK;
}

int send_udp(int socket, const struct sockaddr_in *destination_address) {
    if(sendto(socket, NULL, 0, 0 ,destination_address, sizeof(socket)) < 0) {
        fprintf(stderr,"sendto ipv4 failed\n");
        return ERROR;
    }
    return OK;
}

int catch_icmp_response(pcap_t *pcap_handle, unsigned timeout_ms) {
    struct pcap_pkthdr *packet_header;
    const u_char *packet_data;
    struct timeval start_time;

    gettimeofday(&start_time, NULL);

    while (1) {
        if (calculate_elapsed_ms(start_time) > timeout_ms) {
            return PORT_STATUS_OPEN; // No response within timeout
        }

        int result = pcap_next_ex(pcap_handle, &packet_header, &packet_data);
        if (result == 0) continue;
        if (result < 0) return ERROR;

        int link_header_length = get_link_header_length(pcap_datalink(pcap_handle));
        if ((int)packet_header->caplen <= link_header_length) continue;

        const uint8_t *ip_start = packet_data + link_header_length;
        uint8_t version = IP_VERSION_FROM_FIRST_BYTE(ip_start[0]);

        if (IS_IPV4_VERSION(version)) {
            struct iphdr *ip_hdr = (struct iphdr *)ip_start;
            int ip_hlen = ip_hdr->ihl * 4;
            if (ip_hdr->protocol != IPPROTO_ICMP) continue;
            if ((int)packet_header->caplen < link_header_length + ip_hlen + 8) continue;

            const uint8_t *icmp_start = ip_start + ip_hlen;
            uint8_t icmp_type = icmp_start[0];
            uint8_t icmp_code = icmp_start[1];

            // ICMP type 3, code 3 = port unreachable
            if (icmp_type == 3 && icmp_code == 3) {
                // Optionally, check embedded UDP header for port match
                return PORT_STATUS_CLOSED;
            }
        } else if (IS_IPV6_VERSION(version)) {
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ip_start;
            if (ip6_hdr->ip6_nxt != IPPROTO_ICMPV6) continue;
            const uint8_t *icmp6_start = ip_start + sizeof(struct ip6_hdr);
            uint8_t icmp6_type = icmp6_start[0];
            uint8_t icmp6_code = icmp6_start[1];

            // ICMPv6 type 1, code 4 = port unreachable
            if (icmp6_type == 1 && icmp6_code == 4) {
                return PORT_STATUS_CLOSED;
            }
        }
    }
}


int scan_udp_ports_for_one_target(const Config *config, struct addrinfo *target) {
    char target_ip_string[INET6_ADDRSTRLEN];
    ip_string_from_sockaddr(target->ai_addr, target_ip_string, sizeof(target_ip_string));

    int udp_socket = create_udp_socket(target);
    if (udp_socket < 0) {
        return ERROR;
    }

    pcap_t *handle = initialize_pcap_listener(config, target);
    if (handle == NULL) {
        return ERROR;
    }

    for (int port_number = 1; port_number < MAX_PORTS; port_number++) {
        if (!config->udp_ports[port_number]) continue;


        int result = catch_icmp_response(handle, config->timeout_ms);
        if (result == ERROR) {
            fprintf(stderr, "Error capturing ICMP response\n");
            close(udp_socket);
            pcap_close(handle);
            return ERROR;
        } else if (result == PORT_STATUS_OPEN) {
            printf("%s udp %d open\n", target_ip_string, port_number);
        } else {
            printf("%s udp %d closed\n", target_ip_string, port_number);
        }
    }

    return OK;
}


int run_udp_scan(const Config *config) {

    struct addrinfo *targets = NULL;
    if (resolve_udp_target(config, &targets) != OK) {
        fprintf(stderr, "Error resolving target\n");
        return ERROR;
    }

    for (struct addrinfo *target = targets; target != NULL; target = target->ai_next) {
        if (target->ai_family != AF_INET && target->ai_family != AF_INET6) {
            fprintf(stderr, "Skipping unsupported address family\n");
            continue;
        }

        if (scan_udp_ports_for_one_target(config, target) == ERROR) {
            fprintf(stderr, "Error scanning target\n");
            continue;
        }
    }

    printf("UDP scan is not fully implemented yet. %s\n", config->server_hostname);
    // freeaddrinfo(targets);
    return OK;
}
