import socket
import struct

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = s.recvfrom(65535)
        des_mac, src_mac, proto, data = ethernet_frame(raw_data)
        if proto == 8: 
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print("*****")
            print('\tIPv4 Packet: ')
            print('\tVersion: {}\tHeader Length: {}\tTTL: {}\tProtocol: {}'.format(version,header_length,ttl,proto))
            print('\tDestination: AA:BB:CC:DD:EE:FF\tSource: AA:BB:CC:DD:EE:FF')
            print('\tSource: {}\tTarget: {}'.format(src,target))

            # TCP packets
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, offset, flags, data = tcp_segment(data)
                print('\tTCP Segment: ')
                print('\tSource Port: {}\tDestination Port: {}'.format(src_port,dest_port))
                print('\tSequence: {}\tAcknowledgment: {}'.format(sequence,acknowledgment))
                print('\tFlags: {}'.format(get_tcp_flags(flags)))
                print('\tData: {}'.format(data))
                print('*****')

            # UDP packets
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('\tUDP Segment: ')
                print('\tSource Port: {}\tDestination Port: {}'.format(src_port,dest_port))
                print('\tLength: {}'.format(size))
                print('\tData: {}'.format(data))
                print('*****')

            # ICMP packets
            elif proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\tICMP Packet: ')
                print('\tType: {}\tCode: {}\tChecksum: {}'.format(icmp_type,code,checksum))
                print('\tData: {}'.format(data))
                print('*****')

# Unpack the Ethernet frame
def ethernet_frame(raw_data):
    des_addr, src_addr, proto_type = struct.unpack('! 6s 6s H', raw_data[:14])
    des_mac = get_addr(des_addr)
    src_mac = get_addr(src_addr)
    proto = socket.htons(proto_type)
    data = raw_data[14:]
    return des_mac, src_mac, proto, data

# Transform MAC address to human readable format
def get_addr(bytes_addr):
    return ':'.join(map('{:02X}'.format, bytes_addr))

# Unpack IPv4 
def ipv4_packet(raw_data):
    version_header = raw_data[0]
    version = version_header >> 4
    header_length = (version_header & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, ip_add(src), ip_add(target), data

# Transform IP address to human readable format
def ip_add(addr):
    return '.'.join(map(str, addr))

# Unpack ICMP
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, offset, (flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin), data[offset:]

# Unpack UDP
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Function to get TCP flags in readable form
def get_tcp_flags(flags):
    urg, ack, psh, rst, syn, fin = flags
    return 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(urg, ack, psh, rst, syn, fin)


main()