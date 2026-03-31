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

Use `make clean` to remove all compiled binaries and object files

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
  When scanning a TCP port, the program uses libpcap library to capture incoming packets on the specified interface. It sets up a packet filter to only receive relevant TCP packets from the target IP. For each received packet, it checks if the packet is a valid IPv4 or IPv6 TCP segment, and then verifies if the source and destination ports match the expected values. If a SYN+ACK is received, the port is marked as open; if an RST is received, the port is marked as closed; if no response is received within the timeout, the port is considered filtered. The capture runs in non-blocking and immediate mode for responsiveness, and gracefully handles interruptions or errors. During UDP scanning filter only checks ICMP message for IPV4 and ICMP6 for IPV6. If one of those messages received, port is set as closed only when destination port unreachable message was received. Otherwise is port marked as opened, even if timeout was reached.

## Important design decisions

### Pcap library for listening of packets 
  I chose to use the pcap library because it is well-documented, easy to use, and provides a higher-level interface for packet capture compared to using low-level functions like recvfrom. This made implementing packet listening and filtering much simpler and more reliable for my use case.

### Manual crafting of Headers 
  Since the TCP scanning in this project does not perform a full 3-way handshake (it only sends SYN packets and listens for responses), I needed to manually craft the TCP and IPv4 headers for each packet. This approach gives me full control over the contents of the packets, which is essential for implementing a SYN scan. By building my own header structures, I can set fields like source port, sequence number, flags, and window size exactly as needed. This headers are inspired by protocol standards (RFC 793 for TCP, RFC 791 for IPv4).

  Manual crafting is necessary because standard socket functions (like connect/send) handle header creation automatically and expect a full connection to be established, which is not suitable for our scanning. By constructing the headers myself, I can avoid completing the handshake, minimize detection, and analyze responses precisely.

  For IPv6, the operating system handles the IPv6 header when using raw sockets, so only the TCP header needs to be crafted manually. This simplifies the process for IPv6.

### Usage of preset values
  For sending packets, I have chosen to use a fixed source port (54321) that is unlikely to conflict with common used ports, making it a safe choice for custom scanning. Since packets are crafted manually, I also set a fixed sequence number (123456789) to simplify tracking and debugging responses. The sliding window size is set to 65535, the maximum possible value, that is considered as standard option.

### Handling checksum
  Because we crafted tcp packets manually, the operating system does not automatically calculate and fill in these checksum column. Checksum allows the receiver to detect corrupted packets. Without correct valus our packets could be ignored.
  For correct calculation I used pseudo header that contains important information such as source IP, destination IP, protocol and length. Those pseudo headers are not actually sent, but they are used for correct checksum computation. This part was needed for reliability.

### Changing link header lenght
  The scanner figures out the correct size of the link-layer header for each captured packet by checking the link type provided by libpcap. This ensures packets are parsed correctly on `Ethernet`, `loopback` or `Linux cooked` interfaces. Currently, only these three types are supported, but the code can be extended to handle more link types.

### Checking target availability
  Before sending TCP packets, program tries to connect UDP socket to check, if it can reach destination. I am not sure, if this is a proper way of doing it, but i assumed it might me clever to check it before unnecessary sending packets.

### Choosing own local ip adress based on interface
  Explained in the `Using automatic local IP adresses` part

### Timeout
  Timeout handling in this scanner is implemented using the gettimeofday function. Before sending a packet, the current time is recorded. The program then repeatedly checks for a response, and after each check, it calculates the elapsed time by comparing the current time to the recorded start time. If the elapsed time exceeds the user-specified timeout, the port is considered `filtered` in TCP and `open` in UDP.


## Tests

### Test Suite Overview
  The L4-scanner project includes comprehensive tests covering both normal operation and edge cases. 

#### The test suite consists of:
  - #### Bash script tests:
    - A bash script that verifies the parsing of user arguments and checks for correct error handling and output.
  - #### C unit and integration tests (using Criterion):
    - Unit tests:
      - Simple unit tests for core functions (see test_parsing.c)
    - Input parsing tests:
      - Tests that validate the program’s response to both correct and incorrect user input, ensuring proper exit codes and output (see exit_codes.c).
    - Network behavior tests:
      - Tests simulating various network scenarios to verify correct handling of expected and unexpected network responses (see network_errors.c).

  The test suite structure was created with help from AI, but all the actual test cases and scenarios were written manually by me.

### Tests enviroment 
  - Tests should run only in LINUX enviroment
  - There are not any known kernel or hardware preferences
  - Compiler : GCC
  - Libraries :
       - libpcap-dev (for program binary)
       - libcriterion-dev (for unit tests)
  - Tests use binary file from source code

### Running tests
  To run all tests, use `make test` in the root directory. This will automatically build and execute all test files, showing results for each test suite.


### Inputs, Expected Outputs, and Actual Outputs (with Examples)
  Test can be used in different enviroments. Tests automatically detects available active interfaces, and uses them during test cases

- #### Inputs:
  - Command-line: `./ipk-L4-scan -i eth0 -t 80 127.0.0.1`
  - Command-line: `./ipk-L4-scan -i eth0 -u 53,99999 127.0.0.1` (invalid port)
  - Command-line: `./ipk-L4-scan -t 80 127.0.0.1` (missing interface)

- #### Expected Outputs:
  - For valid scan (port open):
    - `127.0.0.1 80 tcp open`
  - For valid scan (port closed):
    - `127.0.0.1 80 tcp closed`
  - For invalid port:
    - Error message: `Invalid port value`
    - Exit code: non-zero
  - For missing interface:
    - Error message: `Missing interface name`
    - Exit code: non-zero

- #### Actual Outputs:
  - The program prints results and errors as plain text to the terminal.
  - Example output for a successful scan:
    - `127.0.0.1 80 tcp open`
  - Example output for an error:
    - `Missing interface name`
  - Bash and Criterion tests check that the actual output matches the expected output for each test case, reporting PASS/FAIL accordingly.


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

In my implementation, I used the checksum algorithm (see addr_helpers.c) as described in RFC 1071: https://tools.ietf.org/html/rfc1071

The pcap initialization function (see tcp_scan.c) was inspired by examples from https://www.tcpdump.org/pcap.html

### AI HELP
  Additionally, AI was used for studying as well. It helped with understanding topic and explaining problemic parts of TCP/UDP communication, but also helped with explaining  C libraries, structures and possible usage options. 

