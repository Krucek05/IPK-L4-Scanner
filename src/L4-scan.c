// This file is part of the IPK Project 1 - OMEGA: L4 Scanner.
// Author: Kristian Rucek > xrucekk00

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

int TCP_ports(void) {

    return 0;
}


int UDP_ports(void) {

    return 0;
}

int timeout(void) {

    return 0;
}

int argument_parsing(int argc, char *argv[]){
    if(argc == 1){
        fprintf(stderr, "Error: No arguments provided. Use -h or --help for usage information.\n");
        return 1;
    }

    for(int i = 1; i < argc; i++){
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            print_help();
            return 0;
        }

        if (strcmp(argv[i], "-i") == 0){
            
            interface()
        }

        if (strcmp(argv[i], "-t") == 0){
            TCP_ports();
        }

        if (strcmp(argv[i], "-u") == 0){
            UDP_ports();
        }

        if (strcmp(argv[i], "-w") == 0){
            timeout();
        }
    }

    return 0;
}


int main(int argc, char *argv[]) {
    
    argument_parsing(argc, argv);

    return 0;
}