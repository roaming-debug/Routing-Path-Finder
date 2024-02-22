import argparse
import datetime
import logging
import random
import select
import socket
import struct
import time

# Parse command line arguments
parser = argparse.ArgumentParser(description='Network Emulator')
parser.add_argument('-p', dest='port', type=int,
                    help='Port number for emulator')
parser.add_argument('-f', dest='filename',
                    help='Name of the forwarding table file')
parser.add_argument('-l', dest='log_filename',
                    help='Name of the log file', default='log01')
args = parser.parse_args()

# Initialize logging
logging.basicConfig(filename=args.log_filename, level=logging.INFO)

# Create UDP socket
emulator_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
emulator_socket.bind(('0.0.0.0', args.port))

inputs = [emulator_socket]
outputs = []
exceptions = []

own_ipaddr = socket.gethostbyname(socket.gethostname())


def ip_to_uint32(ip):
    bytes = socket.inet_aton(ip)
    return struct.unpack("!I", bytes)[0]


def uint32_to_ip(ipn):
    bytes = struct.pack("!I", ipn)
    return socket.inet_ntoa(bytes)


topology = {}
original_neigbors = []
forwarding_table = {}
largest_timestamp_neighbor = {}
largest_sequece_number_LSP = {}
sending_hello_delay = 2 # every sending_hello_delay seconds, send hello to the neighbors
sending_hello_lasttime = 0
sending_lsp_lasttime = time.time()

def readtopology():
    global topology
    with open(args.filename, 'r') as file:
        for line in file:
            nodes = line.strip().split()
            current_node = nodes[0].split(',')
            current_node = (current_node[0], int(current_node[1]))
            topology[current_node] = []
            for neighbor in nodes[1:]:
                neighbor_ip, neighbor_port = neighbor.split(',')
                topology[current_node].append((neighbor_ip, int(neighbor_port)))
            if current_node == (own_ipaddr, args.port):
                for neighbor in nodes[1:]:
                    neighbor_ip, neighbor_port = neighbor.split(',')
                    original_neigbors.append((neighbor_ip, int(neighbor_port)))

def buildForwardTable():
    global topology
    global forwarding_table
    forwarding_table.clear()
    tentative = []
    for neighbor in topology[(own_ipaddr, args.port)]:
        neighbor_ip, neighbor_port = neighbor
        # Destination, cost, Next Hop
        tentative.append((neighbor_ip, neighbor_port, 1, neighbor_ip, neighbor_port))
    confirmed = set()
    confirmed.add((own_ipaddr, args.port))
    while len(tentative) > 0:
        tmp_confirmed = None
        i_rm = None
        mincost = 10000000
        for i in range(len(tentative)):
            dst_ip, dst_port, cost, next_ip, next_port = tentative[i]
            if mincost >= cost:
                mincost = cost
                tmp_confirmed = tentative[i]
                i_rm = i
        tentative.pop(i_rm)
        dst_ip, dst_port, cost, next_ip, next_port = tmp_confirmed
        
        forwarding_table[(dst_ip, dst_port)] = (next_ip, next_port, cost)
        confirmed.add((dst_ip, dst_port))
        for neighbor in topology[(dst_ip, dst_port)]:
            neighbor_ip, neighbor_port = neighbor
            if (neighbor_ip, neighbor_port) in confirmed:
                continue
            no_match = True
            for i in range(len(tentative)):
                t_dst_ip, t_dst_port, t_cost, t_next_ip, t_next_port = tentative[i]
                if t_dst_ip == neighbor_ip and t_dst_port == neighbor_port:
                    if cost + 1 < t_cost:
                        tentative[i] = (t_dst_ip, t_dst_port, cost+1, next_ip, next_port)
                    no_match = False
            if no_match:
                tentative.append((neighbor_ip, neighbor_port, 1+cost, next_ip, next_port))
    print_topology_forwarding()

def print_topology_forwarding():
    topology_res = 'Topology:\n'
    for key, value in topology.items():
        if len(value) == 0:
            continue
        topology_res += f'{key[0]},{key[1]}'
        for neighbor in value:
            topology_res += f' {neighbor[0]},{neighbor[1]}'
        topology_res += '\n'
    print(topology_res)
    print('Forwarding table:')
    for key, value in forwarding_table.items():
        print(f'{key[0]},{key[1]} {value[0]},{value[1]}')
    print('\n')

def log(err, packet):
    priority, source_ip, source_port, destination_ip, destination_port, payload_length, _ = struct.unpack(
        "=BIHIHI{}s".format(len(packet)-17), packet)
    source_ip = uint32_to_ip(source_ip)
    destination_ip = uint32_to_ip(destination_ip)
    logging.info(f'\n{err}\n'
                 + f"time: {datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
                 + f'Priority: {priority}\n'
                 + f'Source: {socket.gethostbyaddr(source_ip)}:{source_port}\n'
                 + f'Destination: {socket.gethostbyaddr(destination_ip)}:{destination_port}\n'
                 + f'Length: {payload_length}\n')

def forwardpacket(packet, dst_ip, dst_port):
    if (dst_ip, dst_port) not in forwarding_table:
        log('Packet dropped (no forwarding entry found)', packet)
        return
    next_ip, next_port, _ = forwarding_table[(dst_ip, dst_port)]
    emulator_socket.sendto(packet, (next_ip, next_port))

lsp_seq_num = 0
def send_LSP_to_neighbors():
    global lsp_seq_num
    neighbor_list = ''
    for i in range(len(topology[(own_ipaddr, args.port)])):
        ip, port = topology[(own_ipaddr, args.port)][i]
        neighbor_list += f'{ip},{port}'
        if i != len(topology[(own_ipaddr, args.port)])-1:
            neighbor_list += ' '
    # print(f'neighbor_list: {neighbor_list}')
    neighbor_list = neighbor_list.encode()
    inner_packet = struct.pack("=cII{}s".format(len(neighbor_list)), b'L', lsp_seq_num, 64, neighbor_list)
    # destination address and port do not matter
    packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)), \
        1, ip_to_uint32(own_ipaddr), args.port, \
            ip_to_uint32(own_ipaddr), args.port, len(inner_packet), inner_packet)
    for item in topology[(own_ipaddr, args.port)]:
        emulator_socket.sendto(packet, item)
    lsp_seq_num += 1

readtopology()
buildForwardTable()
# set the timestamp to be the current time
for neighbor in original_neigbors:
    largest_timestamp_neighbor[neighbor] = time.time()
    
while True:
    readable, writable, exceptional = select.select(
        inputs, outputs, exceptions, 1/100)
    for s in readable:
        if s is emulator_socket:
            try:
                # Receive packet from network
                packet, sender_info = emulator_socket.recvfrom(4096)
                # Extract packet information
                priority, source_ip, source_port, destination_ip, destination_port, payload_length, inner_packet = struct.unpack(
                    "=BIHIHI{}s".format(len(packet)-17), packet)
                packet_type, sequence_number, payload_length, payload = struct.unpack(
                    "=cII{}s".format(len(inner_packet)-9), inner_packet)
                source_ip = uint32_to_ip(source_ip)
                destination_ip = uint32_to_ip(destination_ip)
                topology_changed = False
                if packet_type == b'D' or packet_type == b'E' or packet_type == b'A' or packet_type == b'R':
                    forwardpacket(packet, destination_ip, destination_port)
                elif packet_type == b'H':
                    largest_timestamp_neighbor[(source_ip, source_port)] = time.time()
                    # add the neighbor to the topology
                    if (source_ip, source_port) not in topology[(own_ipaddr, args.port)]:
                        topology[(own_ipaddr, args.port)].append((source_ip, source_port))
                        topology_changed = True
                    if (own_ipaddr, args.port) not in topology[(source_ip, source_port)]:
                        topology[(source_ip, source_port)].append((own_ipaddr, args.port))
                        topology_changed = True
                    if topology_changed:
                        buildForwardTable()
                        send_LSP_to_neighbors()
                elif packet_type == b'L':
                    ttl = payload_length
                    if (source_ip, source_port) not in largest_sequece_number_LSP:
                        largest_sequece_number_LSP[(source_ip, source_port)] = sequence_number
                    elif largest_sequece_number_LSP[(source_ip, source_port)] < sequence_number:
                        largest_sequece_number_LSP[(source_ip, source_port)] = sequence_number
                    else:
                        continue
                    # update topology
                    neighbor_list = payload.decode()
                    nodes = neighbor_list.strip().split()
                    for node in nodes:
                        neighbor_ip, neighbor_port = node.strip().split(',')
                        neighbor_port = int(neighbor_port)
                        if (neighbor_ip, neighbor_port) not in topology[(source_ip, source_port)]:
                            topology[(source_ip, source_port)].append((neighbor_ip, neighbor_port))
                            topology_changed = True
                        if (source_ip, source_port) not in topology[(neighbor_ip, neighbor_port)]:
                            topology[(neighbor_ip, neighbor_port)].append((source_ip, source_port))
                            topology_changed = True
                    for i in range(len(nodes)):
                        node_ip, node_port = nodes[i].strip().split(',')
                        nodes[i] = (node_ip, int(node_port))
                    for node in topology[(source_ip, source_port)][:]:
                        if node not in nodes:
                            topology[(source_ip, source_port)].remove(node)
                            topology[node].remove((source_ip, source_port))
                            topology_changed = True
                    if topology_changed:
                        # print(neighbor_list)
                        # print(nodes)
                        # print(source_ip, source_port)
                        buildForwardTable()
                    for neighbor in topology[(own_ipaddr, args.port)]:
                        if neighbor != sender_info:
                            forwardpacket(packet, neighbor[0], neighbor[1])
                elif packet_type == b'T':
                    ttl = sequence_number  # in TTL packets, sequece number is replaced by TTL
                    if ttl == 0:
                        inner_packet = struct.pack(
                            "=cII{}s".format(0), b'T', ttl, 0, b'\0')
                        packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)),
                                             1, ip_to_uint32(
                                                 own_ipaddr), args.port,
                                             ip_to_uint32(destination_ip), destination_port, len(inner_packet), inner_packet)
                        emulator_socket.sendto(
                            packet, (source_ip, source_port))
                    else:
                        ttl -= 1
                        inner_packet = struct.pack(
                            "=cII{}s".format(0), b'T', ttl, 0, b'\0')
                        packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)),
                                             1, ip_to_uint32(source_ip), source_port,
                                             ip_to_uint32(destination_ip), destination_port, len(inner_packet), inner_packet)
                        forwardpacket(packet, destination_ip, destination_port)
            except KeyboardInterrupt:
                print("Emulator terminated.")
                break
    
    # send hello at regular interval
    if time.time() - sending_hello_lasttime >= sending_hello_delay:
        sending_hello_lasttime = time.time()
        inner_packet = struct.pack("=cII{}s".format(0), b'H', 0, 0, b'\0')
        for neighbor in original_neigbors:
            packet = struct.pack("=BIHIHI{}s".format(len(inner_packet)),
                1, ip_to_uint32(
                own_ipaddr), args.port,
                ip_to_uint32(neighbor[0]), neighbor[1], len(inner_packet), inner_packet)
            forwardpacket(packet, neighbor[0], neighbor[1])
    # check timestamp of hello
    updated_topology = False
    for neighbor in topology[(own_ipaddr, args.port)][:]:
        if time.time() - largest_timestamp_neighbor[neighbor] > sending_hello_delay+1:
            if neighbor in topology[(own_ipaddr, args.port)]:
                topology[(own_ipaddr, args.port)].remove(neighbor)
                updated_topology = True
            topology[neighbor].clear()
            for key, value in topology.items():
                for item in value:
                    if item == neighbor:
                        topology[key].remove(neighbor)
                        updated_topology = True
    if updated_topology:
        buildForwardTable()
        send_LSP_to_neighbors()
    if time.time() - sending_lsp_lasttime >= 100 and not updated_topology:
        sending_lsp_lasttime = time.time()
        send_LSP_to_neighbors()
                        
