/**
 * This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
 * // 23.3. 2026 IPK 2026, FIT VUT Brno
 *  Author: Kristian Rucek > xrucekk00
 */

#include "L4-scan.h"

volatile sig_atomic_t program_terminated = 0;

void print_help(Config *config) {
    printf("----------------------------------------------------------------\n");
    printf("IPK Project 1 - OMEGA: L4 Port Scanner\n");
    printf("\n");
    printf("Usage:\n");
    printf("  ./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT]\n");
    printf("  ./ipk-L4-scan -i\n");
    printf("  ./ipk-L4-scan -h | --help\n");
    printf("\n");
    printf("Options:\n");
    printf("  -i INTERFACE   Network interface to use for scanning.\n");
    printf("                 If specified without a value and no other arguments are\n");
    printf("                 given, lists active interfaces and exits (exit code 0).\n");
    printf("  -t PORTS       TCP ports to scan.\n");
    printf("                 Examples: -t 22   -t 22,23,24   -t 1-1024\n");
    printf("  -u PORTS       UDP ports to scan.\n");
    printf("                 Examples: -u 53   -u 53,67      -u 1-65535\n");
    printf("  -w TIMEOUT     Timeout in milliseconds to wait for a response per port.\n");
    printf("                 Optional. Default: 1000 ms.\n");
    printf("  -h, --help     Print this help message and exit (exit code 0).\n");
    printf("\n");
    printf("Arguments:\n");
    printf("  HOST           Hostname or IPv4/IPv6 address of the device to scan.\n");
    printf("\n");
    printf("Output format:\n");
    printf("  <IP> <port> <tcp|udp> <open|closed|filtered>\n");
    printf("\n");
    printf("Examples:\n");
    printf("  ./ipk-L4-scan -i eth0 -u 53,67 2001:67c:1220:809::93e5:917\n");
    printf("  ./ipk-L4-scan -i eth0 -w 1000 -t 80,443,8080 www.vutbr.cz\n");
    printf("\n");
    config->exit_after_print = true;
    if (config->exit_after_print) {
        printf("---------------Finishing program execution---------------------\n");
    }
}

int parse_single_port(const char *str) {
    char *end;
    long port = strtol(str, &end, 10);
    if (end == str || *end != '\0' || port < MIN_PORT_NUMBER || port > MAX_PORT_NUMBER) {
        fprintf(stderr, "Error: Invalid port '%s'. Must be 1-65535.\n", str);
        return PORT_ERROR; // EX_USAGE is not suitable here since this function is used after initial parsing, so we return -1 to indicate invalid port
    }
    return (int)port;
}

int parse_ports(Config *config, bool *ports) {
    int port_string_length = strlen(config->port_string);
    char *port_string_copy = malloc(port_string_length + 1);
    if (!port_string_copy) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return EX_OSERR;
    }

    strcpy(port_string_copy, config->port_string);


    char *token = strtok(port_string_copy, ",");
    while (token != NULL) {
        char *dash = strchr(token, '-');
        if (dash) { // Range of ports
            *dash = '\0';
            int start = parse_single_port(token);
            if (start == PORT_ERROR) {
                free(port_string_copy);
                fprintf(stderr, "Error: Invalid port range start '%s'\n", token);
                return EX_USAGE;
            }
            int end   = parse_single_port(dash + 1);
            if (end == PORT_ERROR) {
                free(port_string_copy);
                fprintf(stderr, "Error: Invalid port range end\n");
                return EX_USAGE;
            }
            if (start < 0 || end < 0 || start > end) {
                free(port_string_copy);
                fprintf(stderr, "Error: Invalid port range \n");
                return EX_USAGE;
            }
            for (int p = start; p <= end; p++)
                ports[p] = true;
        } else {
            int port = parse_single_port(token);
            if (port < 0) { 
                free(port_string_copy);
                return EX_USAGE;
            }
            ports[port] = true;
        }
        token = strtok(NULL, ",");
    }

    free(port_string_copy);
    return EX_OK;
}

int cli_argument_parsing(int argc, char *argv[], Config *config) {
    bool interface_set = false;

    if(argc == 1){
        fprintf(stderr, "Error: No arguments provided. Use -h or --help for usage information.\n");
        return EX_USAGE;
    }

    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            print_help(config);
            return EX_OK;
        }

        if (strcmp(argv[i], "-i") == 0 && !interface_set){
            struct if_nameindex *if_nix = NULL, *ifs = NULL;
            if(i + 1 < argc && argv[i + 1][0] != '-') {
                if_nix = if_nameindex(); // Get list of interfaces
                if (if_nix == NULL) {
                    fprintf(stderr,"if_nameindex");
                    return EX_USAGE;
                }
                config->interface_name = argv[i + 1];
                for (ifs = if_nix; ifs->if_index != 0; ifs++) {
                    if (strcmp(ifs->if_name, config->interface_name) == 0) {
                        interface_set = true;
                        break; // Found the specified interface
                    }
                }
                if_freenameindex(if_nix);
                i++; // Skip the next argument since it's the interface name
            } else {
                if_nix = if_nameindex();
                if (if_nix == NULL) {
                    fprintf(stderr,"if_nameindex");
                    return EX_USAGE;
                }
                if (argc == 2) { 
                    for (ifs = if_nix; ifs->if_index != 0; ifs++) {
                        printf("%s\n", ifs->if_name);
                    }
                    if_freenameindex(if_nix);
                    free(config);
                    exit(EX_OK); 
                } else {
                    if_freenameindex(if_nix);
                    fprintf(stderr, "Error: Missing interface name for -i option.\n");
                    return EX_USAGE;
                }
            }
        }

        else if (strcmp(argv[i], "-t") == 0){
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config->port_string = argv[i + 1];
                i++;
                if (parse_ports(config, config->tcp_ports) != EX_OK)
                    return EX_USAGE;
            } else {
                fprintf(stderr, "Error: Missing port string for -t option.\n");
                return EX_USAGE;
            }

            if(config->order_of_scanning[0] == SCAN_NONE){
                config->order_of_scanning[0] = SCAN_TCP;
            } else if (config->order_of_scanning[0] == SCAN_UDP && config->order_of_scanning[1] == SCAN_NONE){
                config->order_of_scanning[1] = SCAN_TCP;
            }
        }

        else if (strcmp(argv[i], "-u") == 0){
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config->port_string = argv[i + 1];
                i++;
                if (parse_ports(config, config->udp_ports) != EX_OK)
                    return EX_USAGE;
            } else {
                fprintf(stderr, "Error: Missing port string for -u option.\n");
                return EX_USAGE;
            }

            if(config->order_of_scanning[0] == SCAN_NONE){
                config->order_of_scanning[0] = SCAN_UDP;
            } else if (config->order_of_scanning[0] == SCAN_TCP && config->order_of_scanning[1] == SCAN_NONE){
                config->order_of_scanning[1] = SCAN_UDP;
            }

        }

        else if (strcmp(argv[i], "-w") == 0){
            if(i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "Error: Missing timeout value for -w option.\n");
                return EX_USAGE;
            }
            char *timeout_string = argv[i+1];
            char *end;
            long timeout = strtol(timeout_string, &end, 10);
            if(*end == 0){
                if(timeout > 0){
                    config->timeout_ms = timeout;
                } else {
                    fprintf(stderr, "Error: Wrong timeout input\n");
                return EX_USAGE;
                }

            } else {
                fprintf(stderr, "Error: Wrong timeout input\n");
                return EX_USAGE;
            }
            i++;
        }
        else {
             if (config->server_hostname != NULL) {
                fprintf(stderr, "Error: Multiple hosts specified.\n");
                return EX_USAGE;
            }
            config->server_hostname = argv[i];
        }
    }

    if (config->server_hostname == NULL) {
        fprintf(stderr, "Error: HOST is strictly required.\n");
        return EX_USAGE;
    }

    if (!interface_set) {
        fprintf(stderr, "Error: Correct network interface must be specified with -i option.\n");
        return EX_USAGE;
    }

    if (config->order_of_scanning[0] == SCAN_NONE) {
        fprintf(stderr, "Error: At least one of -t PORTS or -u PORTS must be specified.\n");
        return EX_USAGE;
    }

    return EX_OK;
}

// Calculate elapsed time in milliseconds since the provided start time
long calculate_elapsed_ms(struct timeval start_time) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    
    return (current_time.tv_sec - start_time.tv_sec) * 1000 + 
           (current_time.tv_usec - start_time.tv_usec) / 1000;
}

// Sets program termination flag on signal
void handle_signal() {
    program_terminated = 1;
}

#ifndef UNIT_TEST
int main(int argc, char *argv[]) {
    struct sigaction sig_action;

    sig_action.sa_handler = handle_signal;
    sigemptyset(&sig_action.sa_mask);
    sig_action.sa_flags = 0;

    sigaction(SIGINT, &sig_action, NULL);
    sigaction(SIGTERM, &sig_action, NULL);


    Config *config = calloc(1, sizeof(Config));
    if (!config) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return EX_OSERR;
    }
    
    config->timeout_ms = DEFAULT_TIMEOUT_MS;
    config->order_of_scanning[0] = SCAN_NONE;
    config->order_of_scanning[1] = SCAN_NONE;

    int parse_status = cli_argument_parsing(argc, argv, config);
    if (parse_status == EX_USAGE) {
        free(config);
        return EX_USAGE;
    } else if (parse_status == EX_OSERR) {
        free(config);
        return EX_OSERR;
    }


    if (config->exit_after_print) {
        free(config);
        return EX_OK;
    }

    for (int i = 0; i < MAX_PROCESSED_SCANNS && config->order_of_scanning[i] != SCAN_NONE; i++) {
        if (program_terminated) {
            fprintf(stderr, "\nScan interrupted before completion\n Finishing program \n");
            free(config);
            return PROGRAM_TERMINATED_ERROR;  // SIGINT/SIGTERM received
        }
        
        int status = (config->order_of_scanning[i] == SCAN_TCP) ? run_tcp_scan(config) : run_udp_scan(config);
        
        if (status == EX_TEMPFAIL) {
            free(config);
            fprintf(stderr, "\nScan interrupted before completion\n Finishing program \n");
            return PROGRAM_TERMINATED_ERROR; // SIGINT/SIGTERM received
        }
        
        if (status != EX_OK) {
            free(config);
            return EX_OSERR;
        }
    }

    free(config);
    return EX_OK;
}
#endif