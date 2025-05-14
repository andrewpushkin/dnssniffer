# DNS Sniffer

A lightweight DNS packet capture and analysis tool that captures and decodes DNS traffic on network interfaces.

## Features

- Capture DNS packets on any network interface
- Support for IPv4 and IPv6
- DNS name compression handling
- Support for A and AAAA records
- Detailed packet validation
- Configurable logging levels
- Signal handling for clean shutdown

## Prerequisites

- Linux operating system
- Root privileges for packet capture
- **Required packages:**
  - `libpcap-dev` (for packet capture)
  - `cmake` (>= 3.10)
  - `build-essential` (for compiler and build tools)
  - `git` (to fetch dependencies)
  - `googletest` (for building and running tests)

On Debian/Ubuntu, install with:
```bash
sudo apt update
sudo apt install libpcap-dev cmake build-essential git
```

> **Note:** Googletest is automatically downloaded and built if you enable tests (see below).

## Building

### Build without tests (default)

```bash
mkdir build
cd build
cmake -DBUILD_TESTING=OFF ..
make
```

### Build with tests

```bash
mkdir build
cd build
cmake -DBUILD_TESTING=ON ..
make
```

To run tests:
```bash
cd build
ctest
```

## Usage

```bash
sudo ./dnssniffer -i <interface> [-v level] [-h]
```

### Options

- `-i <interface>`: Network interface to capture on (required)
- `-v <level>`: Verbosity level (0-3, default: 0)
  - 0: errors only
  - 1: + warnings
  - 2: + info
  - 3: + debug
- `-h`: Show help message

### Example

```bash
sudo ./dnssniffer -i eth0 -v 2
```

## Security Considerations

1. **Root Privileges**: This program requires root privileges to capture packets. Run with sudo or as root.
2. **Packet Validation**: All DNS packets are validated before processing to prevent buffer overflows and malformed packets.
3. **Resource Limits**: Built-in limits for:
   - Maximum DNS name length
   - Maximum number of IP addresses stored
   - Maximum number of compression pointer jumps

## Error Handling

The program uses detailed error codes:
- DNS_SUCCESS (0): Operation successful
- DNS_ERROR_GENERAL (-1): Generic error
- DNS_ERROR_COMPRESSION (-2): DNS name compression error
- DNS_ERROR_MALFORMED (-3): Malformed packet
- DNS_ERROR_BUFFER (-4): Buffer overflow prevented
- DNS_ERROR_VALIDATION (-5): Packet validation failed

## Signal Handling

The program handles the following signals:
- SIGINT (Ctrl+C): Clean shutdown
- SIGTERM: Clean shutdown

## Cross Compilation

To cross-compile for another architecture (e.g., ARM), specify the toolchain file with CMake:

```bash
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=<path-to-toolchain-file> ..
make
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.