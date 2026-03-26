# Project 1 - OMEGA: L4 Scanner

## Short project overview
This project is a simple TCP and UDP network L4 scanner. Main inspiration of this project is tool called nmap. This application receives user data in CLI and behaviour of application depends on given datas. User chooses ports to be scanned, interface, timeout and Host name. After receiving all data, application starts scanning and prints results to stdout. Host is supported with IPv4/IPv6 addresses but DNS resolution is supported as well. During TCP scan uses only SYN packets and does not finish three-way handshake. UDP scanning is filtered with icmp message. 


## Build and run instructions 

### Build 

#### Requirements
- GCC with C17 support
- libpcap-dev
- libcriterion-dev (for tests)

To run this project is neccessary to build binary file. To do so use `make` in root directory of this project. Binary is called `ipk-L4-scan`.
For successfull build is `gcc -std=c17` needed with additional -lpcap library for listening of incoming packets.

#### Compiler flags
- -D_DEFAULT_SOURCE
- -D_GNU_SOURCE

Flags important for including posix and GNU extensions

### Run

To run this program, root privileges are required. Any order of parameters can be given :

##### User options :
```bash
sudo ./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT]

where :
  -i INTERFACE - Network interface to use (required)
   $ ./ipk-L4-scan -i  -> Show list of all available active inetrfaces
   -------------------------------------------------------------------
  -t PORTS - TCP ports to scan (comma-separated or ranges)
   -------------------------------------------------------------------
  -u PORTS - UDP ports to scan (comma-separated or ranges)
   -------------------------------------------------------------------
  -w TIMEOUT - Timeout in milliseconds (default: 1000ms)
   -------------------------------------------------------------------
  -h, --help - Display help message
   -------------------------------------------------------------------
  HOST - Target hostname or IP address (required)
   -------------------------------------------------------------------

Output :
  <IP> <port> <tcp|udp> <open|closed|filtered>
``` 

Example of usage :
```bash
sudo ./ipk-L4-scan -i eth0 -u 53,67
sudo ./ipk-L4-scan -i eth0 -w 1000 -t 80,443,8080 www.vutbr.cz
```

## Implemented features and behavior

## Important design decisions

## Tests

## Known limitations


## References
### These sources were used mainly for studing topics and understanding different C libraries, structures and functions

* https://nmap.org/book/synscan.html
* https://nmap.org/nmap_doc.html#port_unreach
* https://www.rfc-editor.org/rfc/rfc793.txt
* https://nmap.org/book/tcpip-ref.html#tcp-header
* https://www.tcpdump.org/pcap.html
* https://www.networkacademy.io/ccna/ipv6/ipv6-address-types
* https://en.cppreference.com/w/c.html
* https://man7.org/linux/man-pages/index.html
* https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
* https://github.com/PacktPublishing/Hands-On-Network-Programming-with-C/tree/master/chap04
* https://datatracker.ietf.org/doc/html/rfc792
* https://nmap.org/book/scan-methods-udp-scan.html

