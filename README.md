# Network Packet Sniffer

## Description

This is a **network packet sniffer** built in Python, which listens to raw network traffic and decodes Ethernet frames, IPv4 packets, TCP segments, UDP packets, and ICMP packets. The script can print detailed information about these packets, such as source and destination IP addresses, ports, flags, and more.

This tool is intended to help understand and inspect network traffic for educational purposes or troubleshooting network issues. It's especially useful for anyone interested in **network programming**, **network security**, and **protocol analysis**.

## Features

- **Ethernet Frame Parsing**: Extracts source and destination MAC addresses and the protocol type.
- **IPv4 Packet Parsing**: Decodes IPv4 header and extracts information such as source and destination IPs.
- **TCP Segment Parsing**: Extracts TCP-specific information including flags, ports, and sequence numbers.
- **UDP Segment Parsing**: Extracts UDP-specific information including ports and length.
- **ICMP Packet Parsing**: Extracts ICMP-specific details like type, code, and checksum.

## Requirements

- **Python 3.x**  
  Make sure you have Python 3.x installed. This script uses the `socket` and `struct` modules, which are part of Python's standard library.
  
- **Root Privileges**  
  Since this script listens to raw network packets, you need to run the script with **root privileges** or as an administrator on your machine.

### Install Dependencies

There are no external dependencies for this project since it relies only on Python’s built-in libraries (`socket`, `struct`).

## Usage

### 1. Clone the repository

```
git clone https://github.com/H1gg5Th3B0S0N/Packet-Sniffer.git
cd network-packet-sniffer
```

### 2. Run the Sniffer

To run the packet sniffer, simply execute the script with the following command:

```
sudo python3 packet_sniffer.py
```

*Note: `sudo` is required for capturing raw packets on most systems.*

### 3. Analyze Packets

Once the script is running, it will continuously listen for incoming packets on your network interface and print out detailed information about each packet it captures.

#### Output Format

The output will display detailed packet information in the following format:

```
*****
    IPv4 Packet: 
    Version: 4    Header Length: 20    TTL: 64    Protocol: 6
    Destination: AA:BB:CC:DD:EE:FF    Source: AA:BB:CC:DD:EE:FF
    Source: 192.168.1.1    Target: 192.168.1.2
    TCP Segment: 
    Source Port: 12345    Destination Port: 80
    Sequence: 12345    Acknowledgment: 54321
    Flags: URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 1, FIN: 0
    Data: <Packet Data>
*****
```
### 4. Stop the Sniffer

To stop the script, use `Ctrl + C` in the terminal.

## Example Output

Here’s an example of what the output might look like when the script captures a TCP packet:

```
*****
    IPv4 Packet: 
    Version: 4    Header Length: 20    TTL: 64    Protocol: 6
    Destination: 00:14:22:01:23:45    Source: 00:25:9C:1F:33:48
    Source: 192.168.1.2    Target: 192.168.1.1
    TCP Segment: 
    Source Port: 80    Destination Port: 12345
    Sequence: 234567    Acknowledgment: 890123
    Flags: URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 1, FIN: 0
    Data: <Some Data>
*****
```
## Code Explanation

- **Main Function (`main`)**: Initiates a raw socket connection and listens for incoming packets. For each packet received, it processes the packet and identifies whether it’s IPv4, TCP, UDP, or ICMP, and prints detailed information.
- **Helper Functions**: These functions unpack and decode various network protocols:
  - `ethernet_frame(raw_data)`: Unpacks the Ethernet frame.
  - `ipv4_packet(raw_data)`: Unpacks the IPv4 packet and extracts source/destination IP addresses.
  - `icmp_packet(data)`: Extracts ICMP packet details.
  - `tcp_segment(data)`: Extracts TCP segment details including flags and sequence numbers.
  - `udp_segment(data)`: Extracts UDP segment details.
  - `get_tcp_flags(flags)`: Converts TCP flag bits into a readable format.

## Contribution

Feel free to fork this repository and submit a pull request if you would like to contribute. Contributions to enhance functionality, fix bugs, or improve documentation are welcome!

### Areas to Improve

- **Support for more protocols**: Currently, the script supports Ethernet, IPv4, TCP, UDP, and ICMP. Adding support for other protocols like ARP or IPv6 would improve the tool.
- **GUI**: Creating a graphical user interface (GUI) for real-time packet visualization could make this tool more user-friendly.
