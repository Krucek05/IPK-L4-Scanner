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

### Error handling during parsing of user input
  #### Following situations ends up with error :
  - Missing interface name
  - Using interface, that is not currently available
  - Missing port string
  - Multiple hosts or interfaces specified
  - Invalid range of ports -> <1,65535> are allowed
  - Invalid value of ports -> Must be integer value
  - Invalid range values   -> Start must be lower than end 

### Addtional CLI support :
  - Flexible port selection: Supports both single ports and port ranges, which can be     specified in any order and multiple times for both TCP and UDP scans.
  - Multiple -t and -u options: Allows specifying scanning ports with repeated `-t/-u` parameters; all specified ports are merged and scanned.
  - User-defined scan order: The order of TCP/UDP scanning follows the order in which `-t` and `-u` options are provided by the user.
  - Automatic sorting: Ports are scanned in numerical order from lowest to highest, regardless of input order.
  - Graceful help: Both `-h` and `--help` print a detailed help message and exit cleanly, even if any combination of input was given.

### Termination of program :
  If the program was prematurely terminated with `SIGTERM/SIGINT` signal, it will gracefully handle the interruption: ongoing tasks are safely stopped, a message is printed to inform the user about the termination, and the program exits cleanly. This ensures no resources are leaked and the user is always notified when the scan is interrupted.

### Support for both IPV4/IPV6 :
  The scanner automatically detects and supports both IPv4 and IPv6 addresses. If a DNS address is used, the program resolves all available IP addresses associated with the hostname and prints the scan results for each address separately. Protocol handling is also dynamically managed for different packets.

### Using automatic local IP adresses
  The scanner automatically selects the most suitable local IPv4 or IPv6 address for the specified network interface. For IPv6, the program prefers global addresses but will use loopback or link-local addresses if necessary. This improves reliability across different network setups. For UDP scans, the operating system automatically handles local address selection. For TCP scans, the address selection is managed internally by the program.

### Receiving response :
  When scanning a TCP port, the program uses libpcap library to capture incoming packets on the specified interface. It sets up a packet filter to only receive relevant TCP packets from the target IP. For each received packet, it checks if the packet is a valid IPv4 or IPv6 TCP segment, and then verifies if the source and destination ports match the expected values. If a SYN+ACK is received, the port is marked as open; if an RST is received, the port is marked as closed; if no response is received within the timeout, the port is considered filtered. The capture runs in non-blocking and immediate mode for responsiveness, and gracefully handles interruptions or errors. During UDP scanning filter only checks ICMP message for IPV4 and ICMP6 for IPV6. If one of those messages received, port is set as closed. Otherwise is port marked as opened, even if timeout was reached.

## Important design decisions

To be done

## Tests

To be done

## Known limitations

### There are not any known limitations


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

### AI HELP
  Additionally, AI was used for studying as well. It helped with understanding topic and explaining problemic parts of TCP/UDP communication, but also helped with explaining  C libraries, structures and possible usage options. 

