import argparse
import struct
import socket

parser = argparse.ArgumentParser(description='routetrace Application')
parser.add_argument('-a', dest='routetrace_port', type=int, help='Port for routetrace')
parser.add_argument('-b', dest='src_host', help='Source Hostname')
parser.add_argument('-c', dest='src_port', type=int, help='Source Port')
parser.add_argument('-d', dest='dest_host', help='Destination Hostname')
parser.add_argument('-e', dest='dest_port', type=int, help='Destination Port')
parser.add_argument('-f', dest='debug_option', type=int, help='Debug Option')
args = parser.parse_args()


def ip_to_uint32(ip):
   bytes = socket.inet_aton(ip)
   return struct.unpack("!I", bytes)[0]
def uint32_to_ip(ipn):
   bytes = struct.pack("!I", ipn)
   return socket.inet_ntoa(bytes)

def unpack(packet):
    _, source_ip, source_port, destination_ip, destination_port, _, inner_packet = struct.unpack("=BIHIHI{}s".format(len(packet)-17), packet)
    packet_type, ttl, _ = struct.unpack("=cII", inner_packet)
    source_ip = uint32_to_ip(source_ip)
    destination_ip = uint32_to_ip(destination_ip)
    return ttl, source_ip, source_port, destination_ip, destination_port


def handle_debug_option(packet, send_or_response):
    if args.debug_option == 1:
        ttl, source_ip, source_port, destination_ip, destination_port = unpack(packet)
        if send_or_response == 0:
            print(f"Sent: TTL: {ttl}, Source: {source_ip}:{source_port}, Destination: {destination_ip}:{destination_port}")
        else:
            print(f"Received: TTL: {ttl}, Source: {source_ip}:{source_port}, Destination: {destination_ip}:{destination_port}")
        

def create_routetrace_packet(src_ip, src_port, dest_ip, dest_port, ttl):
    # The second field is TTL instead of sequence number
    inner_packet = struct.pack("=cII{}s".format(0), b'T', ttl, 0, b'\0')
    packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), \
        1, ip_to_uint32(src_ip), src_port, \
        ip_to_uint32(dest_ip), dest_port, len(inner_packet), inner_packet)
    return packet

def routetrace(src_ip, src_port, dest_ip, dest_port, debug_option):
    routetrace_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    routetrace_socket.bind(('0.0.0.0', src_port))

    ttl = 0

    while True:
        packet = create_routetrace_packet(src_ip, src_port, dest_ip, dest_port, ttl)
        handle_debug_option(packet, 0)
        routetrace_socket.sendto(packet, (socket.gethostbyname(args.src_host), args.src_port))

        response, _ = routetrace_socket.recvfrom(4096)
        handle_debug_option(response, 1)
        _, source_ip, source_port, _, _ = unpack(response)
        print(f'{ttl + 1} {source_ip} {source_port}')
        
        # Print response deatils for debug option

        # Check if the destination was reached
        if response_contains_destination(response, dest_ip, dest_port):
            break
        else:
            ttl += 1
            # time.sleep(1)

    routetrace_socket.close()

def response_contains_destination(response_packet, dest_ip, dest_port):
    # Unpack response packet and extract fields
    try:
        _, source_ip, source_port, destination_ip, dst_port, _, inner_packet = struct.unpack("=BIHIHI{}s".format(len(response_packet)-17), response_packet)
        packet_type, ttl, _ = struct.unpack("=cII", inner_packet)
        source_ip = uint32_to_ip(source_ip)
        destination_ip = uint32_to_ip(destination_ip)

        # Check if recieved packet matches dest IP and port
        if source_ip == dest_ip and source_port == dest_port:
            return True
        else:
            return False
        
    except struct.error as e:
        print(f"Error unpakcing response packet: {e}")
        return False


routetrace(socket.gethostbyname(args.src_host), args.routetrace_port, socket.gethostbyname(args.dest_host), \
    args.dest_port, args.debug_option)
