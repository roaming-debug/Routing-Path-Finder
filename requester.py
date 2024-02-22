import socket
import argparse
import time
import struct
import datetime

# Parse command line arguments
parser = argparse.ArgumentParser(description='Requester for file transfer')
parser.add_argument('-p', dest='port', type=int, help='Port number for requester')
parser.add_argument('-o', dest='file_name', help='Name of the file being requested')
parser.add_argument('-f', dest='f_hostname', help='The host name of the emulator')
parser.add_argument('-e', dest='f_port', type=int, help='The port of the emulator')
parser.add_argument('-w', dest='window_size', type=int, help="the requester's window size")
args = parser.parse_args()

# Create UDP socket
requester_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
requester_socket.bind(("0.0.0.0", args.port))

# Requester address and port
requester_address = ('', args.port)

# Tracker information
tracker_file = 'tracker.txt'

def ip_to_uint32(ip):
   bytes = socket.inet_aton(ip)
   return struct.unpack("!I", bytes)[0]
def uint32_to_ip(ipn):
   bytes = struct.pack("!I", ipn)
   return socket.inet_ntoa(bytes)

# Read tracker file and find sender information
file_sender_info = []
with open(tracker_file, 'r') as tracker:
    for line in tracker:
        filename, sender_id, sender_hostname, sender_port = line.split()
        if filename == args.file_name:
            file_sender_info.append((int(sender_id), socket.gethostbyname(sender_hostname), int(sender_port)))
            # sender_address = (socket.gethostbyname(sender_hostname), int(sender_port))
    if len(file_sender_info) == 0:
        print(f'File "{args.file_name}" not found in the tracker.')
        requester_socket.close()
        exit()

filename = args.file_name
file_sender_info.sort(key=lambda info: info[0])

# Create a new file to write received data
received_file = open(args.file_name, 'wb')

own_ipaddr = socket.gethostbyname(socket.gethostname())

for file_sender in file_sender_info:
    # Request file parts from sender
    request_packet = struct.pack("=cII{}s".format(len(filename)), \
        b'R', socket.htonl(0), args.window_size, filename.encode())
    request_packet = struct.pack("=BIHIHI{}s".format(len(request_packet)), \
        1, ip_to_uint32(own_ipaddr), args.port, \
            ip_to_uint32(file_sender[1]), file_sender[2], len(request_packet), request_packet)
    
    sender_address = (socket.gethostbyname(args.f_hostname), args.f_port)
    requester_socket.sendto(request_packet, sender_address)

    # Variables to store statistics
    start_time = None
    total_data_packets = 0
    total_data_bytes = 0
    
    receive_buffer = {}
    sending_hello_delay = 2 # every sending_hello_delay seconds, send hello to the neighbors
    sending_hello_lasttime = 0

    while True:
        if time.time() - sending_hello_lasttime >= sending_hello_delay:
            sending_hello_lasttime = time.time()
            inner_packet = struct.pack("=cII{}s".format(0), b'H', 0, 0, b'\0')
            packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), 1, 
                            ip_to_uint32(own_ipaddr), 
                            args.port, ip_to_uint32(sender_address[0]),
                            args.f_port, 
                            len(inner_packet), inner_packet)

            requester_socket.sendto(packet, sender_address)

        # Receive packet from sender
        packet, sender_info = requester_socket.recvfrom(4096)
        # Extract packet information
        priority, source_ip, source_port, destination_ip, destination_port, inner_packet_length, inner_packet = struct.unpack("=BIHIHI{}s".format(len(packet)-17), packet)
        source_ip = uint32_to_ip(source_ip)
        destination_ip = uint32_to_ip(destination_ip)
        if destination_ip != own_ipaddr:
            print('Error: destination ip is not for this machine')
            continue
        packet_type, sequence_number, payload_length, payload = struct.unpack("=cII{}s".format(len(inner_packet)-9), inner_packet)
        sequence_number = socket.ntohl(sequence_number)
        
        ack_packet = struct.pack("=cII{}s".format(0), b'A', socket.htonl(sequence_number), 0, b'\0')
        request_packet = struct.pack("=BIHIHI{}s".format(len(ack_packet)), \
            1, ip_to_uint32(own_ipaddr), args.port, \
            ip_to_uint32(file_sender[1]), file_sender[2], len(ack_packet), ack_packet)
        
        # Record start time
        if start_time is None:
            start_time = time.time()

        # Update statistics
        if packet_type == b'D':
            total_data_packets += 1
            total_data_bytes += payload_length
            receive_buffer[sequence_number] = payload

        # Check for END packet
        if packet_type == b'E' and payload_length == 0:
            # Calculate test duration
            duration = time.time() - start_time

            # Print summary information
            print("Summary")
            print(f'Sender:                 {file_sender[1]}:{file_sender[2]}')
            print(f'Total Data packets:     {total_data_packets}')
            print(f'Total Data bytes:       {total_data_bytes}')
            print(f'Average packets/second: {total_data_packets / duration:.2f}')
            print(f'Duration of the test:   {duration:.2f} seconds\n')

            break
        
        # send ACK
        requester_socket.sendto(request_packet, sender_address)

                
    receive_buffer = dict(sorted(receive_buffer.items()))
    for k, v in receive_buffer.items():
        received_file.write(v)

# Close sockets and file
requester_socket.close()
received_file.close()
