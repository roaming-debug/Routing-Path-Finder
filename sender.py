import datetime
import select
import socket
import struct
import time
import argparse
import os.path

def ip_to_uint32(ip):
   bytes = socket.inet_aton(ip)
   return struct.unpack("!I", bytes)[0]
def uint32_to_ip(ipn):
   bytes = struct.pack("!I", ipn)
   return socket.inet_ntoa(bytes)

# Parse command line arguments
parser = argparse.ArgumentParser(description='Sender for file transfer')
parser.add_argument('-p', dest='port', type=int, help='Port number for sender')
parser.add_argument('-g', dest='requester_port', type=int, help='Port number of requester')
parser.add_argument('-r', dest='rate', type=int, help='Number of packets to be sent per second')
parser.add_argument('-q', dest='seq_no', type=int, help='Initial sequence number')
parser.add_argument('-l', dest='length', type=int, help='Length of payload in bytes')
parser.add_argument('-f', dest='emulator_hostname', help='Emulator hostname')
parser.add_argument('-e', dest='emulator_port', type=int, help='Emulator port number')
parser.add_argument('-i', dest='priority', type=int, help='Packet priority')
parser.add_argument('-t', dest='timeout', type=int, help='Timeout for retransmission in milliseconds')
args = parser.parse_args()

if args.port <= 2049 or args.port >= 65536 or args.requester_port <= 2049 or args.requester_port >= 65536:
    print("port value is not valid")

# Create UDP socket
sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender_socket.bind(("0.0.0.0", args.port))

# Get Filename and requester ip address

# Requester address and port
requester_socket = (socket.gethostbyname(args.emulator_hostname), args.emulator_port)

src_ipaddr = socket.gethostbyname(socket.gethostname())


retransmission_times = 0
transmission_times = 0

sending_hello_delay = 2 # every sending_hello_delay seconds, send hello to the neighbors
sending_hello_lasttime = 0
while True:
    readable, writable, exceptional = select.select([sender_socket], [], [], 1/100)
    if len(readable) != 0:
        packet, requester_info = sender_socket.recvfrom(4096)
        priority, source_ip, source_port, destination_ip, destination_port, inner_packet_length, inner_packet = struct.unpack("=BIHIHI{}s".format(len(packet)-17), packet)
        packet_type, sequence_number, window_size, filename = struct.unpack("=cII{}s".format(len(inner_packet)-9), inner_packet)
        sequence_number = socket.ntohl(sequence_number)
        if packet_type == b'R':
            break
    if time.time() - sending_hello_lasttime >= sending_hello_delay:
        sending_hello_lasttime = time.time()
        inner_packet = struct.pack("=cII{}s".format(0), b'H', 0, 0, b'\0')
        packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), 1, 
                            ip_to_uint32(src_ipaddr), 
                            args.port, ip_to_uint32(requester_socket[0]), 
                            requester_socket[1], 
                            len(inner_packet), inner_packet)
        sender_socket.sendto(packet, requester_socket)
    
    
    
dst_ipaddr = uint32_to_ip(source_ip)
dst_port = source_port


# Open and read file
if os.path.isfile(filename):
    with open(filename, 'rb') as file:
        file_data = file.read()
else:
    file_data = []

# Calculate number of packets
num_packets = len(file_data) // args.length + 1 * (len(file_data) % args.length != 0)

last_sendts = 0
def send_packet(index):
    global transmission_times
    global last_sendts
    # Prepare packet header and payload
    packet_type = b'D'
    sequence_number = 1 + index
    payload = file_data[index * args.length: (index + 1) * args.length]

    # Construct packet
    inner_packet = struct.pack("=cII{}s".format(len(payload)), \
        packet_type, socket.htonl(sequence_number), len(payload), payload)
    packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), args.priority, \
        ip_to_uint32(src_ipaddr), args.port, \
        ip_to_uint32(dst_ipaddr), dst_port, len(inner_packet), inner_packet)
    
    # Send packet to requester
    # while ensuring the interval time between two packets
    crrtime = time.time()
    # print((crrtime-last_sendts)*1000)
    time.sleep(max(0, 1/args.rate-crrtime+last_sendts))
    sender_socket.sendto(packet, requester_socket)
    last_sendts = crrtime
    transmission_times += 1

# Send data packets
for i in range(0, num_packets, window_size):
    window = {}
    for j in range(window_size):
        if i + j >= num_packets:
            break
        send_packet(i+j)
        window[i + j] = (0, time.time()*1000+args.timeout)
        # Sleep to achieve the desired sending rate
        time.sleep(1 / args.rate)

    # print(window)
    sending_hello_delay = 2 # every sending_hello_delay seconds, send hello to the neighbors
    sending_hello_lasttime = 0


    while len(window) != 0:
        readable, _, _ = select.select([sender_socket], [], [], 1/10000)
        if len(readable) == 0:
            crrtime = time.time()*1000
            for key, p_info in list(window.items()):
                if p_info[1] < crrtime:
                    # print(key, p_info[1], crrtime)
                    if p_info[0] == 5:
                        print(f"Failed to send the packet with the sequence number {key+1}")
                        window.pop(key)
                    else:
                        # print('resend')
                        retransmission_times += 1
                        send_packet(key)
                        window[key] = (p_info[0]+1, time.time()*1000+args.timeout)
            if time.time() - sending_hello_lasttime >= sending_hello_delay:
                sending_hello_lasttime = time.time()
                inner_packet = struct.pack("=cII{}s".format(0), b'H', 0, 0, b'\0')
                packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), 1, 
                                    ip_to_uint32(src_ipaddr), 
                                    args.port, ip_to_uint32(requester_socket[0]), 
                                    requester_socket[1], 
                                    len(inner_packet), inner_packet)
                sender_socket.sendto(packet, requester_socket)
            continue
        packet, _ = readable[0].recvfrom(4096)
        priority, source_ip, source_port, destination_ip, destination_port, inner_packet_length, inner_packet = struct.unpack("=BIHIHI{}s".format(len(packet)-17), packet)
        received_data = struct.unpack("=cII{}s".format(len(inner_packet)-9), inner_packet)
        packet_type = received_data[0]
        sequence_number = socket.ntohl(received_data[1])
        if packet_type == b'A' and sequence_number - 1 in window:
            window.pop(sequence_number-1)

sequence_number = 1 + num_packets
# Send END packet
endinner_packet = struct.pack("=cII", b'E', socket.htonl(sequence_number), 0)
end_packet = struct.pack("=BIHIHI{}s".format(len(endinner_packet)), args.priority, \
    ip_to_uint32(src_ipaddr), args.port, \
        ip_to_uint32(dst_ipaddr), dst_port, len(endinner_packet), endinner_packet)

crrtime = time.time()
time.sleep(max(0, 1/args.rate-crrtime+last_sendts))
sender_socket.sendto(end_packet, requester_socket)
last_sendts = crrtime

# Print END packet information
print("END Packet\n"
    + f"send time:      {datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
    + f"requester addr: {requester_socket[0]}:{requester_socket[1]}\n"
    + f"sequence num:   {sequence_number}\n"
    + f"length:         0\n"
    + f"payload:        \n")

# Print Loss rate information
print(f"Loss rate: {retransmission_times/transmission_times}\n"
      + f"retransmission times: {retransmission_times}\n"
      + f"transmission times: {transmission_times}")

# Close socket
sender_socket.close()
