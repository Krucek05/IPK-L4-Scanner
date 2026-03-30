/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */

#include "L4-scan.h"
#include "tcp_scan.h"
#include "addr_helpers.h"


/* ========================= Helpers ========================= */

// Determines the local IP address
// Tries to pick the best source IP for target interface
// ( for ipv4, the primary usable address that is not loopback, 
//for ipv6, the first global address, but if none found, we can fallback to link-local or loopback)
int get_local_ip_address(const char *target_interface_name, int family, void *result_ip) {
    struct ifaddrs *interface_list_head;
    struct ifaddrs *current_interface;
    bool ipv4_candidate_found = false;
    struct in_addr ipv4_candidate;
    bool ipv6_candidate_found = false;
    struct in6_addr ipv6_candidate;

    if (result_ip == NULL || (family != AF_INET && family != AF_INET6)) {
        return EX_OSERR;
    }

    if (getifaddrs(&interface_list_head) == -1) {
        fprintf(stderr,"getifaddrs\n");
        freeifaddrs(interface_list_head);
        return EX_OSERR;
    }
    
    if (target_interface_name == NULL) {
        freeifaddrs(interface_list_head);
        return EX_OSERR;
    }

    for (current_interface = interface_list_head; current_interface != NULL; current_interface = current_interface->ifa_next) {
        if (current_interface->ifa_addr == NULL || current_interface->ifa_addr->sa_family != family) {
            continue;
        }

        if (strcmp(current_interface->ifa_name, target_interface_name) != 0) {
            continue;
        }

        // For IPv4, prefer the primary usable address that is not loopback
        if (family == AF_INET) {
            const struct sockaddr_in *ipv4_address = (const struct sockaddr_in *)current_interface->ifa_addr;
            // For IPv4, we should use the primary usable address that is not loopback
            if ((current_interface->ifa_flags & IFF_LOOPBACK) == 0 && ipv4_address->sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
                *(struct in_addr *)result_ip = ipv4_address->sin_addr;
                freeifaddrs(interface_list_head);
                return EX_OK;
            }

            // Keep first matching IPv4 as fallback (needed e.g. for lo -> 127.0.0.1).
            if (!ipv4_candidate_found) {
                ipv4_candidate = ipv4_address->sin_addr;
                ipv4_candidate_found = true;
            }
            continue;
        }
        // For IPv6, we should use the first global address on the selected interface, 
        // but if none found, we can fallback to link-local or loopback
        const struct sockaddr_in6 *ipv6_address = (const struct sockaddr_in6 *)current_interface->ifa_addr;
        // IPv6 should use the first global address on the selected interface.
        if (IN6_IS_ADDR_LINKLOCAL(&ipv6_address->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&ipv6_address->sin6_addr)) {
            if (!ipv6_candidate_found) {
                ipv6_candidate = ipv6_address->sin6_addr;
                ipv6_candidate_found = true;
            }
            continue;
        }

        *(struct in6_addr *)result_ip = ipv6_address->sin6_addr;
        freeifaddrs(interface_list_head);
        return EX_OK;
    }

    if (family == AF_INET && ipv4_candidate_found) {
        *(struct in_addr *)result_ip = ipv4_candidate;
        freeifaddrs(interface_list_head);
        return EX_OK;
    }

    if (family == AF_INET6 && ipv6_candidate_found) {
        *(struct in6_addr *)result_ip = ipv6_candidate;
        freeifaddrs(interface_list_head);
        return EX_OK;
    }

    freeifaddrs(interface_list_head);
    return EX_OSERR;
}

static void initialize_tcp_syn_header(Tcp_header *tcp_header, uint16_t source_port) {
    memset(tcp_header, 0, sizeof(Tcp_header));

    tcp_header->source_port = htons(source_port);
    tcp_header->seq_num = htonl(SEQ_NUM);
    tcp_header->ack_num = 0;
    tcp_header->data_offset = TCP_DATA_OFFSET(sizeof(Tcp_header));
    tcp_header->flags = TCP_FLAG_SYN;
    tcp_header->window_size = htons(SLIDING_WINDOW_SIZE);
    tcp_header->urgent_pointer = 0;

    // Checksum will be calculated by caller after setting destination_port.
}

static int can_reach_target_on_interface(int family, const struct sockaddr *target_address,
    socklen_t target_address_length, const char *interface_name) {

    // We can check if the target is reachable on the specified interface by attempting to connect a UDP socket to the target.
    int probe_socket = socket(family, SOCK_DGRAM, 0);
    if (probe_socket < 0) {
        return EX_OSERR;
    }

    if (interface_name != NULL && bind_to_interface(probe_socket, interface_name) != EX_OK) {
        fprintf(stderr,"bind_to_interface failed\n");
        close(probe_socket);
        return EX_OSERR;
    }

    if (connect(probe_socket, target_address, target_address_length) != 0) {
        fprintf(stderr,"connect failed\n");
        close(probe_socket);
        return EX_OSERR;
    }

    close(probe_socket);
    return EX_OK;
}

/* ========================= Packet Builders ========================= */

// Initializes the IP and TCP headers for a SYN packet to the target
int create_tcp_syn_packet_ipv4(struct in_addr source_ip, struct in_addr destination_ip, uint16_t source_port,
    Ipv4_header *ip_header, Tcp_header *tcp_header) {

    memset(ip_header, 0, sizeof(Ipv4_header));

    ip_header->version_ihl = IPV4_VERSION_IHL(sizeof(Ipv4_header));
    ip_header->dscp_ecn = 0;
    ip_header->total_length = htons(sizeof(Ipv4_header) + sizeof(Tcp_header));
    ip_header->identification = htons(MY_RANDOM_PORT); // Just a random number for identification
    ip_header->flags_fragment_offset = htons(0);
    ip_header->ttl = DEFAULT_IP_TTL;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->source_ip = source_ip;
    ip_header->destination_ip = destination_ip;
    ip_header->header_checksum = checksum(ip_header, sizeof(Ipv4_header));

    initialize_tcp_syn_header(tcp_header, source_port);

    return EX_OK;
}

// Initializes TCP header for an IPv6 SYN packet (IPv6 header is provided by kernel)
int create_tcp_syn_packet_ipv6(struct in6_addr source_ip, struct in6_addr destination_ip, uint16_t source_port,
    Tcp_header *tcp_header) {
    (void)source_ip;
    (void)destination_ip;
    initialize_tcp_syn_header(tcp_header, source_port);

    return EX_OK;
}

/* ========================= Packet Senders ========================= */

// Send a raw TCP SYN packet to the target IPv6 address.
// For AF_INET6 raw TCP socket, kernel builds IPv6 header.
int send_tcp_syn_ipv6(int raw_socket, const struct sockaddr_in6 *destination_address, Tcp_header *tcp_header) {
    if (sendto(raw_socket, tcp_header, sizeof(Tcp_header), 0,
               (const struct sockaddr *)destination_address, sizeof(*destination_address)) < 0) {
        fprintf(stderr, "sendto ipv6 failed\n");
        return EX_OSERR;
    }
    return EX_OK;
}

// Send a raw TCP SYN packet to the target IPv4 address
int send_tcp_syn_ipv4(int raw_socket, const struct sockaddr_in *destination_address, Ipv4_header *ip_header, Tcp_header *tcp_header) {
    char packet[sizeof(Ipv4_header) + sizeof(Tcp_header)];
    memcpy(packet, ip_header, sizeof(Ipv4_header));
    memcpy(packet + sizeof(Ipv4_header), tcp_header, sizeof(Tcp_header));

    struct sockaddr_in connection_destination_address;
    memcpy(&connection_destination_address, destination_address, sizeof(struct sockaddr_in));
    
    if (sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&connection_destination_address, sizeof(connection_destination_address)) < 0) {
        fprintf(stderr,"sendto ipv4 failed\n");
        return EX_OSERR;
    }

    return EX_OK;
}

/* ========================= Target and Capture Helpers ========================= */

// Resolves the target hostname to a list of addresses (IPv4 and/or IPv6) based on the configuration
int resolve_tcp_targets(const Config *config, struct addrinfo **targets) {
    struct addrinfo hints; // suggested parameters for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6.
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(config->server_hostname, NULL, &hints, targets) != 0) {
        freeaddrinfo(*targets);
        return EX_OSERR;
    }
    return EX_OK;
}

// Get the length of the link layer header based on the pcap link type
int get_link_header_length(int link_type) {
    switch (link_type) {
        case DLT_LINUX_SLL:
            return PCAP_LINK_HEADER_LINUX_SLL;
        case DLT_NULL:
            return PCAP_LINK_HEADER_LOOPBACK;
        default:
            return PCAP_LINK_HEADER_ETHERNET;
    }
}

// Listen for incoming packets and check if they are responses to our SYN packet for the specified target port
int catch_tcp_response(pcap_t *pcap_handle, uint16_t my_port, uint16_t target_port, unsigned timeout_ms) {
    struct pcap_pkthdr *packet_header;
    const u_char *packet_data;
    struct timeval start_time;
    
    gettimeofday(&start_time, NULL);

    while (!program_terminated) {
        if (calculate_elapsed_ms(start_time) > timeout_ms) {
            return PORT_STATUS_FILTERED;
        }

        int result = pcap_next_ex(pcap_handle, &packet_header, &packet_data);
        if (result == 0) continue;
        if (result < 0) return EX_OSERR;

        int link_header_length = get_link_header_length(pcap_datalink(pcap_handle));
        if ((int)packet_header->caplen <= link_header_length) continue; // Not enough data for IP header

        const uint8_t *ip_start = packet_data + link_header_length;
        uint8_t version = IP_VERSION_FROM_FIRST_BYTE(ip_start[0]);
        struct tcphdr *tcp_header = NULL;

        if (IS_IPV4_VERSION(version)) {
            if ((int)packet_header->caplen < link_header_length + (int)sizeof(struct iphdr)) continue;

            struct iphdr *ip_hdr = (struct iphdr *)ip_start;
            int ip_hlen = ip_hdr->ihl * 4;

            if (ip_hlen < 20 || (int)packet_header->caplen < link_header_length + ip_hlen + (int)sizeof(struct tcphdr)) continue;
            tcp_header = (struct tcphdr *)(ip_start + ip_hlen);
        } else if (IS_IPV6_VERSION(version)) {
            if ((int)packet_header->caplen < link_header_length + (int)sizeof(struct ip6_hdr) + (int)sizeof(struct tcphdr)) continue;

            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ip_start;
            if (ip6_hdr->ip6_nxt != IPPROTO_TCP) continue;
            tcp_header = (struct tcphdr *)(ip_start + sizeof(struct ip6_hdr));
        } else {
            continue;
        }

        if (ntohs(tcp_header->dest) == my_port && ntohs(tcp_header->source) == target_port) {
            if (tcp_header->syn && tcp_header->ack) return PORT_STATUS_OPEN;
            if (tcp_header->rst) return PORT_STATUS_CLOSED;
            return PORT_STATUS_FILTERED;
        }
    }

    // Signal received during scan
    if (program_terminated) {
        fprintf(stderr, "\nScan interrupted by signal\n");
        return EX_TEMPFAIL;
    }
    return PORT_STATUS_FILTERED;

}

// Initializes a pcap handle for listening to responses from the target IP
// Sets filter to capture TCP packets or ICMP from the target IP and configures timeout and non-blocking mode
// This code was inspired by https://www.tcpdump.org/pcap.html, but adapted for specific use case and requirements
pcap_t *initialize_pcap_listener(const Config *config, struct addrinfo *target, bool is_tcp) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    const char *interface_name = config->interface_name ? config->interface_name : "any";

    pcap_handle = pcap_create(interface_name, error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't create pcap handle for device %s: %s\n", interface_name, error_buffer);
        return NULL;
    }

    // Set snaplen to maximum to ensure we capture the full packet, which is needed to analyze TCP headers correctly
    if (pcap_set_snaplen(pcap_handle, SLIDING_WINDOW_SIZE) != 0) {
        fprintf(stderr, "Warning: Could not set snaplen.\n");
    }
    // Set promiscuous mode to capture all packets on the interface, not just those addressed to us.
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "Warning: Could not set promisc mode.\n");
    }

    // Enable immediate mode to prevent buffering delays
    if (pcap_set_immediate_mode(pcap_handle, 1) != 0) {
        fprintf(stderr, "Warning: Could not set immediate mode.\n"); 
    }

    if (pcap_set_timeout(pcap_handle, config->timeout_ms) != 0) {
        fprintf(stderr, "Warning: Could not set timeout.\n");
    }

    if (pcap_activate(pcap_handle) != 0) {
        fprintf(stderr, "Couldn't activate pcap handle: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return NULL;
    }

    // Set non-blocking mode so pcap_next_ex returns immediately if no packet available
    if (pcap_setnonblock(pcap_handle, 1, NULL) != 0) {
        fprintf(stderr, "Warning: Could not set non-blocking mode\n");
    }

    // Compile and set filter to capture only relevant TCP packets from target IP
    struct bpf_program filter_program;
    int filter_expression_length = 0;
    char filter_expression[PCAP_FILTER_MAX_LENGTH];
    char target_ip_string[INET6_ADDRSTRLEN];
    ip_string_from_sockaddr(target->ai_addr, target_ip_string, sizeof(target_ip_string));
    if (is_tcp) {
        filter_expression_length = snprintf(filter_expression, sizeof(filter_expression), "src host %s and tcp", target_ip_string);
        if (filter_expression_length < 0 || (size_t)filter_expression_length >= sizeof(filter_expression)) {
            fprintf(stderr, "Could not build pcap filter expression\n");
            pcap_close(pcap_handle);
            return NULL;
        }
    } else {
        if (target->ai_family == AF_INET) {
            filter_expression_length = snprintf(filter_expression, sizeof(filter_expression), "src host %s and icmp", target_ip_string);
        } else {
             filter_expression_length = snprintf(filter_expression, sizeof(filter_expression), "src host %s and icmp6", target_ip_string);
        }
        if (filter_expression_length < 0 || (size_t)filter_expression_length >= sizeof(filter_expression)) {
            fprintf(stderr, "Could not build pcap filter expression\n");
            pcap_close(pcap_handle);
            return NULL;
        }
    }
    if (filter_expression_length < 0 || (size_t)filter_expression_length >= sizeof(filter_expression)) {
        fprintf(stderr, "Could not build pcap filter expression\n");
        pcap_close(pcap_handle);
        return NULL;
    }
    
    if (pcap_compile(pcap_handle, &filter_program, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expression, pcap_geterr(pcap_handle));
         pcap_close(pcap_handle);
         return NULL;
    }
    if (pcap_setfilter(pcap_handle, &filter_program) == -1) {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expression, pcap_geterr(pcap_handle));
         pcap_close(pcap_handle);
         return NULL;
    }

    pcap_freecode(&filter_program);

    return pcap_handle;
}

/* ========================= Scan Flow ========================= */

// Scans the specified TCP ports for a single target IP address by sending SYN packets and listening for responses
int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target) {
    char target_ip_string[INET6_ADDRSTRLEN];
    ip_string_from_sockaddr(target->ai_addr, target_ip_string, sizeof(target_ip_string));

    struct in_addr local_ip4;
    struct in6_addr local_ip6;

    if (target->ai_family == AF_INET) {
        if (get_local_ip_address(config->interface_name, AF_INET, &local_ip4) != EX_OK) {
            fprintf(stderr, "Could not determine local IPv4 address.\n");
            return EX_OSERR;
        }
    } else if (target->ai_family == AF_INET6) {
        if (get_local_ip_address(config->interface_name, AF_INET6, &local_ip6) != EX_OK) {
            fprintf(stderr, "Could not determine local IPv6 address.\n");
            return EX_OSERR;
        }
    } else {
        fprintf(stderr, "Unsupported address family for target %s\n", target_ip_string);
        return EX_OSERR;
    }

    if (can_reach_target_on_interface(target->ai_family, target->ai_addr, target->ai_addrlen, config->interface_name) != EX_OK) {
        if (target->ai_family == AF_INET6) {
            fprintf(stderr, "No Ipv6 route to %s via interface %s\n", target_ip_string,
                config->interface_name ? config->interface_name : "any");
        } else {
            fprintf(stderr, "No IPv4 route to %s via interface %s\n", target_ip_string,
                config->interface_name ? config->interface_name : "any");
        }
        return EX_OSERR;
    }

    pcap_t *pcap_handle = initialize_pcap_listener(config, target, true);
    if (pcap_handle == NULL) {
        return EX_OSERR;
    }

    int raw_socket = socket(target->ai_family, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket <= 0) {
        fprintf(stderr, "socket\n");
        pcap_close(pcap_handle);
        return EX_OSERR;
    }

    if (target->ai_family == AF_INET) {
        if (configure_raw_socket(raw_socket, target->ai_family, config->interface_name) != EX_OK) {
            close(raw_socket);
            pcap_close(pcap_handle);
            return EX_OSERR;
        }
    } else {
        if (config->interface_name != NULL && bind_to_interface(raw_socket, config->interface_name) != EX_OK) {
            close(raw_socket);
            pcap_close(pcap_handle);
            return EX_OSERR;
        }
    }

    Tcp_header tcp_header;
    memset(&tcp_header, 0, sizeof(tcp_header));

    struct sockaddr_in *destination4 = (struct sockaddr_in *)target->ai_addr;
    struct sockaddr_in6 *destination6 = (struct sockaddr_in6 *)target->ai_addr;

    Ipv4_header ip_header;
    if (target->ai_family == AF_INET) {
        create_tcp_syn_packet_ipv4(local_ip4, destination4->sin_addr, MY_RANDOM_PORT, &ip_header, &tcp_header);
    } else {
        create_tcp_syn_packet_ipv6(local_ip6, destination6->sin6_addr, MY_RANDOM_PORT, &tcp_header);
    }

    for (int port_number = 1; port_number < MAX_PORTS && !program_terminated; port_number++) {
        if (!config->tcp_ports[port_number]) continue;

        tcp_header.destination_port = htons(port_number);
        tcp_header.checksum = 0;

        int send_status = EX_OSERR;
        if (target->ai_family == AF_INET) {
            tcp_header.checksum = checksum_ipv4(local_ip4, destination4->sin_addr,
                IPPROTO_TCP, &tcp_header, sizeof(Tcp_header));
            send_status = send_tcp_syn_ipv4(raw_socket, destination4, &ip_header, &tcp_header);
        } else {
            tcp_header.checksum = checksum_ipv6(local_ip6, destination6->sin6_addr,
                IPPROTO_TCP, &tcp_header, sizeof(Tcp_header));
            send_status = send_tcp_syn_ipv6(raw_socket, destination6, &tcp_header);
        }

        if (send_status != EX_OK) continue;

        int response_status = PORT_STATUS_FILTERED;

        // To improve reliability, we can attempt to catch a response multiple times before concluding the port is filtered
        for (int attempt = 0; attempt < 2; attempt++) {
            response_status = catch_tcp_response(pcap_handle, MY_RANDOM_PORT, port_number, config->timeout_ms);
            if (response_status != PORT_STATUS_FILTERED) break;
        }

        if (response_status == PORT_STATUS_OPEN) {
            printf("%s %d tcp open\n", target_ip_string, port_number);
        } else if (response_status == PORT_STATUS_CLOSED) {
            printf("%s %d tcp closed\n", target_ip_string, port_number);
        } else if (response_status == PORT_STATUS_FILTERED){
            printf("%s %d tcp filtered\n", target_ip_string, port_number);
        } else {
            // Signal interrupted the scan
            close(raw_socket);
            pcap_close(pcap_handle);
            return EX_TEMPFAIL;
        }
    }

    close(raw_socket);
    pcap_close(pcap_handle);
    return EX_OK;
}

// Main TCP scanning function for all targets
int run_tcp_scan(const Config *config) {
    struct addrinfo *targets = NULL;
    if (resolve_tcp_targets(config, &targets) != EX_OK) {
        fprintf(stderr, "Invalid Host name\n");
        return EX_OSERR;
    }

    for (struct addrinfo *target = targets; target != NULL; target = target->ai_next) {
        if (target->ai_family != AF_INET && target->ai_family != AF_INET6) {
            fprintf(stderr, "Skipping unsupported address family\n");
            continue;
        }

        if (scan_tcp_ports_for_one_target(config, target) == EX_OSERR) {
            fprintf(stderr, "Error scanning target\n");
            continue;
        }
    }
    
    freeaddrinfo(targets);
    return EX_OK;
}
