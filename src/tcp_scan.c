// tcp_scan.c - Implements TCP SYN scan functionality using raw sockets and libpcap for packet capture.
// Author: Kristian Rucek > xrucekk00

#include "L4-scan.h"
#include "tcp_scan.h"
#include "addr_helpers.h"
#include <time.h>
#include <sys/time.h>

// check if packet was not corrupted
int checksum (const void *data, size_t length) {
    uint32_t sum = 0;
    const uint16_t *ptr = data;

    while (length > 1) {
        sum += *ptr++;
        length -= 2;
    }

    if (length > 0) {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// Determines the local IP address
int get_local_ip_address(const char *target_interface_name, struct in_addr *result_ip) {
    struct ifaddrs *interface_list_head;
    struct ifaddrs *current_interface;

    if (getifaddrs(&interface_list_head) == -1) {
        fprintf(stderr,"getifaddrs");
        return ERROR;
    }
    
    if (target_interface_name != NULL) {
        for (current_interface = interface_list_head; current_interface != NULL; current_interface = current_interface->ifa_next) {
            if (current_interface->ifa_addr == NULL || current_interface->ifa_addr->sa_family != AF_INET) {
                continue;
            }

            if (strcmp(current_interface->ifa_name, target_interface_name) == 0) {
                *result_ip = ((struct sockaddr_in *)current_interface->ifa_addr)->sin_addr;
                freeifaddrs(interface_list_head);
                return OK;
            }
        }
    }
    return ERROR;
}

// Helper to compute TCP checksum with pseudo-header
uint16_t tcp_checksum(struct in_addr source_ip, struct in_addr destination_ip, Tcp_header *tcp_header) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } pseudo_header;

    pseudo_header.src = source_ip.s_addr;
    pseudo_header.dst = destination_ip.s_addr;
    pseudo_header.zero = 0;
    pseudo_header.proto = IPPROTO_TCP;
    pseudo_header.tcp_len = htons(sizeof(Tcp_header));

    uint8_t buffer[sizeof(pseudo_header) + sizeof(Tcp_header)];
    memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
    memcpy(buffer + sizeof(pseudo_header), tcp_header, sizeof(Tcp_header));

    return checksum(buffer, sizeof(buffer));
}

// send raw TCP SYN packet to target
int send_tcp_syn(int raw_socket, const struct sockaddr_in *destination_address, Ip_header *ip_header, Tcp_header *tcp_header) {
    char packet[sizeof(Ip_header) + sizeof(Tcp_header)];
    memcpy(packet, ip_header, sizeof(Ip_header));
    memcpy(packet + sizeof(Ip_header), tcp_header, sizeof(Tcp_header));

    struct sockaddr_in connection_destination_address;
    memcpy(&connection_destination_address, destination_address, sizeof(struct sockaddr_in));
    
    if (sendto(raw_socket, packet, sizeof(packet), 0, (struct sockaddr *)&connection_destination_address, sizeof(connection_destination_address)) < 0) {
        fprintf(stderr,"sendto");
        return ERROR;
    }

    return OK;
}

int resolve_tcp_targets(const Config *config, struct addrinfo **targets) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(config->server_hostname, NULL, &hints, targets) != 0) {
        return ERROR;
    }
    return OK;
}

long calculate_elapsed_ms(struct timeval start_time) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    return (current_time.tv_sec - start_time.tv_sec) * 1000 + 
           (current_time.tv_usec - start_time.tv_usec) / 1000;
}

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

int catch_tcp_response(pcap_t *pcap_handle, uint16_t my_port, uint16_t target_port, int timeout_ms) {
    struct pcap_pkthdr *packet_header;
    const u_char *packet_data;
    struct timeval start_time;
    
    gettimeofday(&start_time, NULL);

    while (1) {
        if (calculate_elapsed_ms(start_time) > timeout_ms) {
            return PORT_STATUS_FILTERED; // Timeout, no response
        }

        int result = pcap_next_ex(pcap_handle, &packet_header, &packet_data);

        if (result == 0) {
            continue; 
        }
        if (result < 0) {
            return ERROR;
        }

        // Parse packet headers
        int link_header_length = get_link_header_length(pcap_datalink(pcap_handle));

        struct iphdr *ip_header = (struct iphdr *)(packet_data + link_header_length);
        //  ensure it's an IPv4 packet before casting
        if (ip_header->version != 4) continue;

        struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + (ip_header->ihl * 4));

        if (ntohs(tcp_header->dest) == my_port && ntohs(tcp_header->source) == target_port) {
            if (tcp_header->syn && tcp_header->ack) {
                return PORT_STATUS_OPEN;
            }
            if (tcp_header->rst) {
                return PORT_STATUS_CLOSED;
            }
            return PORT_STATUS_FILTERED;
        }
    }
}

int create_tcp_syn_packet(struct in_addr source_ip, struct in_addr dest_ip, uint16_t source_port,
    Ip_header *ip_header, Tcp_header *tcp_header) {

    memset(ip_header, 0, sizeof(Ip_header));
    memset(tcp_header, 0, sizeof(Tcp_header));

    ip_header->version_ihl = IP_VERSION_IHL(sizeof(Ip_header));
    ip_header->dscp_ecn = 0;
    ip_header->total_length = htons(sizeof(Ip_header) + sizeof(Tcp_header));
    ip_header->identification = htons(MY_RANDOM_PORT); // Just a random number for identification
    ip_header->flags_fragment_offset = htons(0);
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->source_ip = source_ip;
    ip_header->dest_ip = dest_ip;
    ip_header->header_checksum = checksum(ip_header, sizeof(Ip_header));

    tcp_header->source_port = htons(source_port);
    // dest_port set by caller per port
    tcp_header->seq_num = htonl(SEQ_NUM);
    tcp_header->ack_num = 0;
    tcp_header->data_offset = TCP_DATA_OFFSET(sizeof(Tcp_header));
    tcp_header->flags = 0x02; // SYN
    tcp_header->window_size = htons(SLIDING_WINDOW_SIZE);
    tcp_header->urgent_pointer = 0;
    
    // Checksum will be calculated by caller after setting dest_port

    return OK;
}

// Initializes a pcap handle for listening to responses from the target IP
// Sets filter to capture only TCP packets from the target IP and configures timeout and non-blocking mode
// This code was inspired by https://www.tcpdump.org/pcap.html and AI suggestions, but adapted for our specific use case and requirements.
pcap_t *initialize_pcap_listener(const Config *config, struct addrinfo *target) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    const char *interface_name = config->interface_name ? config->interface_name : "any";

    pcap_handle = pcap_create(interface_name, error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't create pcap handle for device %s: %s\n", interface_name, error_buffer);
        return NULL;
    }

    if (pcap_set_snaplen(pcap_handle, SLIDING_WINDOW_SIZE) != 0) {
        fprintf(stderr, "Warning: Could not set snaplen.\n");
    }
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
    char filter_expression[100];
    char target_ip_string[INET_ADDRSTRLEN];
    ip_string_from_sockaddr(target->ai_addr, target_ip_string, sizeof(target_ip_string));
    snprintf(filter_expression, sizeof(filter_expression), "src host %s and tcp", target_ip_string);
    
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

    return pcap_handle;
}

int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target) {
    struct in_addr local_ip;
    if (get_local_ip_address(config->interface_name, &local_ip) != OK) {
        fprintf(stderr, "Could not determine local IP address. Checksum calculation would fail.\n");
        return ERROR;
    }

    // Open handle for libpcap
    pcap_t *pcap_handle = initialize_pcap_listener(config, target);
    if (pcap_handle == NULL) {
        return ERROR;
    }

    // Open RAW socket for sending
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket <= 0) {
        fprintf(stderr,"socket");
        pcap_close(pcap_handle);
        return ERROR;
    }

    char target_ip_string[INET_ADDRSTRLEN];
    ip_string_from_sockaddr(target->ai_addr, target_ip_string, sizeof(target_ip_string));

    // Set IP_HDRINCL to tell the kernel we provide our own IP header
    int on = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr,"setsockopt IP_HDRINCL");
        close(raw_socket);
        pcap_close(pcap_handle);
        return ERROR;
    }

    // Bind to interface if specified
    if (config->interface_name && bind_to_interface(raw_socket, config->interface_name) != OK) {
        close(raw_socket);
        pcap_close(pcap_handle);
        return ERROR;
    }

    Ip_header ip_header;
    Tcp_header tcp_header;
    struct sockaddr_in *destination_socket_address = (struct sockaddr_in *)target->ai_addr;

    create_tcp_syn_packet(local_ip, destination_socket_address->sin_addr, MY_RANDOM_PORT, &ip_header, &tcp_header);
   
    for (int port_number=1; port_number<MAX_PORTS; port_number++) {
        if (config->tcp_ports[port_number]) {
            tcp_header.dest_port = htons(port_number);
            tcp_header.checksum = 0; // Reset checksum
            tcp_header.checksum = tcp_checksum(ip_header.source_ip, ip_header.dest_ip, &tcp_header);

            int response_status = PORT_STATUS_FILTERED;
            for (int attempt = 0; attempt < 2; attempt++) {
                send_tcp_syn(raw_socket, destination_socket_address, &ip_header, &tcp_header);
                response_status = catch_tcp_response(pcap_handle, MY_RANDOM_PORT, port_number, config->timeout_ms);
                
                if (response_status != PORT_STATUS_FILTERED) {
                    break;  // Got a definitive answer, don't retry
                }
                // For filtered ports, we can retry a few times to reduce false positives due to packet loss
                // Maybe not necessary...
            }

            if (response_status == PORT_STATUS_OPEN) {
                printf("%s %d tcp open\n", target_ip_string, port_number);
            } else if (response_status == PORT_STATUS_CLOSED) {
                printf("%s %d tcp closed\n", target_ip_string, port_number);
            } else if (response_status == PORT_STATUS_FILTERED) {
                printf("%s %d tcp filtered\n", target_ip_string, port_number); 
            }
        }
    }    
    close(raw_socket);
    pcap_close(pcap_handle);
    return OK;
}


int run_tcp_scan(const Config *config) {
    if (!has_selected_ports(config->tcp_ports)) {
        return OK;
    }

    struct addrinfo *targets = NULL;
    if (resolve_tcp_targets(config, &targets) != OK) {
        return ERROR;
    }

    for (struct addrinfo *target = targets; target != NULL; target = target->ai_next) {
        scan_tcp_ports_for_one_target(config, target);
    }
    
    freeaddrinfo(targets);
    return OK;
}
