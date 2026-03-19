// tcp_scan.c - Implements TCP SYN scan functionality using raw sockets and libpcap for packet capture.
// Author: Kristian Rucek > xrucekk00

#include "L4-scan.h"
#include "tcp_scan.h"
#include "addr_helpers.h"

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
int get_local_ip_address(const char *desired_interface_name, struct in_addr *result_ip) {
    struct ifaddrs *interface_list_head;
    struct ifaddrs *current_interface;

    if (getifaddrs(&interface_list_head) == -1) {
        perror("getifaddrs");
        return ERROR;
    }

    int found = 0;
    
    if (desired_interface_name != NULL) {
        for (current_interface = interface_list_head; current_interface != NULL; current_interface = current_interface->ifa_next) {
            if (current_interface->ifa_addr == NULL || current_interface->ifa_addr->sa_family != AF_INET) {
                continue;
            }

            if (strcmp(current_interface->ifa_name, desired_interface_name) == 0) {
                *result_ip = ((struct sockaddr_in *)current_interface->ifa_addr)->sin_addr;
                found = 1;
                break;
            }
        }
    }

    freeifaddrs(interface_list_head);
    
    if (found) return OK;
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
        perror("sendto");
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

int scan_tcp_ports_for_one_target(const Config *config, struct addrinfo *target) {
    struct in_addr local_ip;
    if (get_local_ip_address(config->interface_name, &local_ip) != OK) {
        fprintf(stderr, "Could not determine local IP address. Checksum calculation would fail.\n");
        return ERROR;
    }

    // Open handle for libpcap
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    const char *interface_name = config->interface_name ? config->interface_name : "any";

    // Use pcap_create and pcap_activate for better control over timeout
    pcap_handle = pcap_create(interface_name, error_buffer);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Couldn't create pcap handle for device %s: %s\n", interface_name, error_buffer);
        return ERROR;
    }

    if (pcap_set_snaplen(pcap_handle, 65535) != 0) {
        fprintf(stderr, "Warning: Could not set snaplen.\n");
    }
    if (pcap_set_promisc(pcap_handle, 1) != 0) {
        fprintf(stderr, "Warning: Could not set promisc mode.\n");
    }

    if (pcap_set_timeout(pcap_handle, config->timeout_ms) != 0) {
        fprintf(stderr, "Warning: Could not set timeout.\n");
    }

    if (pcap_activate(pcap_handle) != 0) {
        fprintf(stderr, "Couldn't activate pcap handle: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return ERROR;
    }

    struct bpf_program filter_program;
    char filter_expression[100];
    char target_ip_string[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &((struct sockaddr_in *)target->ai_addr)->sin_addr, target_ip_string, sizeof(target_ip_string));
    snprintf(filter_expression, sizeof(filter_expression), "src host %s and tcp", target_ip_string);
    
    if (pcap_compile(pcap_handle, &filter_program, filter_expression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
         fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_expression, pcap_geterr(pcap_handle));
         pcap_close(pcap_handle);
         return ERROR;
    }
    if (pcap_setfilter(pcap_handle, &filter_program) == -1) {
         fprintf(stderr, "Couldn't install filter %s: %s\n", filter_expression, pcap_geterr(pcap_handle));
         pcap_close(pcap_handle);
         return ERROR;
    }

    // Open RAW socket for sending
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        perror("socket");
        pcap_close(pcap_handle);
        return ERROR;
    }

    // Set IP_HDRINCL to tell the kernel we provide our own IP header
    int on = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
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

    // Prepare headers for sending
    Ip_header ip_header;
    Tcp_header tcp_header;
    memset(&ip_header, 0, sizeof(ip_header));
    memset(&tcp_header, 0, sizeof(tcp_header));

    ip_header.version_ihl = (4 << 4) | (sizeof(Ip_header) / 4);
    ip_header.dscp_ecn = 0;
    ip_header.total_length = htons(sizeof(Ip_header) + sizeof(Tcp_header));
    ip_header.identification = htons(54321);
    ip_header.flags_fragment_offset = htons(0);
    ip_header.ttl = 64;
    ip_header.protocol = IPPROTO_TCP;

    ip_header.source_ip = local_ip; 
    
    ip_header.dest_ip = ((struct sockaddr_in *)target->ai_addr)->sin_addr;
    ip_header.header_checksum =0; 
    ip_header.header_checksum = checksum(&ip_header, sizeof(Ip_header));

    tcp_header.source_port = htons(MY_RANDOM_PORT);
    tcp_header.seq_num = htonl(SEQ_NUM);
    tcp_header.ack_num = 0;
    tcp_header.data_offset = (sizeof(Tcp_header) / 4) << 4;
    tcp_header.flags = 0x02; // SYN
    tcp_header.window_size = htons(65535);
    tcp_header.urgent_pointer = 0;
   
    struct sockaddr_in *destination_socket_address = (struct sockaddr_in *)target->ai_addr;
    
    struct pcap_pkthdr *pcap_packet_header;
    const u_char *captured_packet;

    for (int port_number=1; port_number<MAX_PORTS; port_number++) {
         if (config->tcp_ports[port_number]) {
             tcp_header.dest_port = htons(port_number);
             tcp_header.checksum = 0; // Reset checksum

             tcp_header.checksum = tcp_checksum(ip_header.source_ip, ip_header.dest_ip, &tcp_header);
             
             send_tcp_syn(raw_socket, destination_socket_address, &ip_header, &tcp_header);

             while(1) {
                 int pcap_result = pcap_next_ex(pcap_handle, &pcap_packet_header, &captured_packet);
                 if (pcap_result == 0) {
                     // Timeout expired
                     printf("%d/tcp filtered\n", port_number);
                     break; 
                 }
                 if (pcap_result < 0) break; // Error

                 // Handle different link types, On Ethernet, the first 14 bytes are MAC addresses
                 int link_header_length = 14;
                 int link_type = pcap_datalink(pcap_handle);
                 if (link_type == DLT_LINUX_SLL) link_header_length = 16;
                 else if (link_type == DLT_NULL) link_header_length = 4;
                 
                 struct iphdr *ip_header_ptr = (struct iphdr*)(captured_packet + link_header_length);
                 struct tcphdr *tcp_header_ptr = (struct tcphdr*)((u_char*)ip_header_ptr + (ip_header_ptr->ihl * 4));

                 // Validate packet is for this probe
                 if (ntohs(tcp_header_ptr->dest) == MY_RANDOM_PORT && ntohs(tcp_header_ptr->source) == port_number) {
                     if (tcp_header_ptr->syn && tcp_header_ptr->ack) {
                         printf("%d/tcp open\n", port_number);
                     } else if (tcp_header_ptr->rst) {
                         printf("%d/tcp closed\n", port_number);
                     } else {
                         printf("%d/tcp filtered\n", port_number);
                     }
                     break; // Done with this port
                 }
                 // If not matching, continue loop (catch next packet)
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
