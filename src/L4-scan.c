// This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
// Author: Kristian Rucek > xrucekk00


#include "L4.scan.h"

void print_help(void) {
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
}

int interface(void) {

    return 0;
}


// print_interfacees(Config *config) {
//     printf("Available interfaces:\n");
//     // todo: implement interface listing

//     return OK;
// }
int parse_single_port(const char *str) {
    char *end;
    long port = strtol(str, &end, 10);
    if (end == str || *end != '\0' || port < 0 || port > 65535) {
        fprintf(stderr, "Error: Invalid port '%s'. Must be 1-65535.\n", str);
        return ERROR;
    }
    return (int)port;
}

int parse_ports(Config *config, bool *ports) {
    int port_string_length = strlen(config->port_string);
    char *port_string_copy = malloc(port_string_length + 1);
    if (!port_string_copy) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return MALLOC_ERROR;
    }

    strcpy(port_string_copy, config->port_string);


    char *token = strtok(port_string_copy, ",");
    while (token != NULL) {
        char *dash = strchr(token, '-');
        if (dash) { // Range of ports
            *dash = '\0';
            int start = parse_single_port(token);
            int end   = parse_single_port(dash + 1);
            if (start < 0 || end < 0 || start > end) {
                free(port_string_copy);
                return ERROR;
            }
            for (int p = start; p <= end; p++)
                ports[p] = true;
        } else {
            int port = parse_single_port(token);
            if (port < 0) { 
                free(port_string_copy);
                return ERROR;
            }
            ports[port] = true;
        }
        token = strtok(NULL, ",");
    }

    free(port_string_copy);
    return OK;
}


int tcp_ports(Config *config) {
    int count = config->timeout_ms;
    return OK;
    count++;
}

int udp_ports(Config *config) {

    int count = config->timeout_ms;

    count++;
    return OK;
}

int timeout(void) {

    return OK;
}

int cli_argument_parsing(int argc, char *argv[], Config *config) {
    if(argc == 1){
        fprintf(stderr, "Error: No arguments provided. Use -h or --help for usage information.\n");
        return ERROR;
    }

    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            print_help();
            return OK;
        }

        if (strcmp(argv[i], "-i") == 0){
            if(i + 1 < argc && argv[i + 1][0] != '-') {
                config->interface_name = argv[i + 1];
                i++; // Skip the next argument since it's the interface name
            }else {
                // print_interfacees(config);
            }
            interface();
        }

        if (strcmp(argv[i], "-t") == 0){
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config->port_string = argv[i + 1];
                i++;
                tcp_ports(config);
                if (parse_ports(config, config->tcp_ports) != OK)
                    return ERROR;
            } else {
                fprintf(stderr, "Error: Missing port string for -t option.\n");
                return ERROR;
            }
        }

        if (strcmp(argv[i], "-u") == 0){
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                config->port_string = argv[i + 1];
                i++;
                udp_ports(config);
                if (parse_ports(config, config->udp_ports) != OK)
                    return ERROR;
            } else {
                fprintf(stderr, "Error: Missing port string for -u option.\n");
                return ERROR;
            }
        }

        if (strcmp(argv[i], "-w") == 0){
            timeout();
        }
    }

    return OK;
}


int main(int argc, char *argv[]) {
    
    Config *config = malloc(sizeof(Config));
    if (!config) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return MALLOC_ERROR;
    }

    if (cli_argument_parsing(argc, argv, config) != OK) {
        free(config);
        return ERROR;
    }

    return 0;
}