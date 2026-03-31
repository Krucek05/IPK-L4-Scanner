## CHANGELOG

### Implemented Functionality
- TCP and UDP L4 port scanning 
- Supports both IPv4 and IPv6, including DNS resolution
- Manual crafting of TCP/IPv4 headers for SYN scan (no full handshake)
- Uses libpcap for packet capture and filtering
- Automatic selection of local IP address based on interface
- Flexible CLI: supports port ranges, multiple -t/-u, custom scan order, and timeouts
- Graceful handling of SIGTERM/SIGINT (clean exit, resource cleanup)
- Error handling for invalid input, missing interface, invalid ports, etc.
- Test suite: Bash scripts for CLI parsing, Criterion C tests for parsing and network behavior

### Known Limitations
- Not known kernel or hardware dependencies
- Not known any limitations 
