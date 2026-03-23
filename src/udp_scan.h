// udp_scan.h - Header for UDP scanning functions
// Author: Kristian Rucek > xrucekk00

#ifndef UDP_SCAN_H
#define UDP_SCAN_H



#include <netinet/in.h>
#include "netinet/ip6.h"
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "addr_helpers.h"
#include "L4-scan.h"
#include "tcp_scan.h"



int run_udp_scan(const Config *config);

#endif /* UDP_SCAN_H */
