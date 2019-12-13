"""
Plugin that takes pcap files and outputs stats

Created on 1 November 2019
@author: Charlie Lewis
"""

import datetime
import json
import os
import shlex
import subprocess
import sys

import pika


def connect_rabbit(host='messenger', port=5672, queue='task_queue'):
    params = pika.ConnectionParameters(host=host, port=port)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    return channel

def send_rabbit_msg(msg, channel, exchange='', routing_key='task_queue'):
    channel.basic_publish(exchange=exchange,
                          routing_key=routing_key,
                          body=json.dumps(msg),
                          properties=pika.BasicProperties(
                          delivery_mode=2,
                         ))
    print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))
    return

def get_version():
    version = ''
    with open('VERSION', 'r') as f:
        for line in f:
            version = line.strip()
    return version

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def parse_capinfos(output):
    results = {'capinfos':{}}
    num_interfaces = 0
    interface_dict = {}
    interface = 0
    interface_name = ''
    for line in output.split('\n'):
        if line == '':
            continue
        if line.startswith('Number of interfaces in file:'):
            num_interfaces = int(line.split(':', 1)[1].strip())
            continue
        if interface < num_interfaces:
            if line.startswith('Interface '):
                interface_name = line.split()[1]
                interface_dict[interface_name] = {}
                continue
            else:
                if line.startswith('Number of packets '):
                    interface += 1
                name, value = line.split(' = ')
                interface_dict[interface_name][name.strip()] = value.strip()
                continue
        name, value = line.split(':', 1)
        results['capinfos'][name.strip()] = value.strip()
    results['capinfos']['interfaces'] = interface_dict
    print(results)
    return results

def run_capinfos(path):
    if os.path.getsize(path) == 0:
       print("pcap file empty, no stats")
       return

    output = ''
    try:
        output = subprocess.check_output(shlex.split(' '.join(['capinfos', path])))
        output = output.decode("utf-8")
    except Exception as e:
        print(str(e))

    results = parse_capinfos(output)
    return results

def get_ether_vendor(mac, lookup_path='nmap-mac-prefixes.txt'):
    """
    Takes a MAC address and looks up and returns the vendor for it.
    """
    mac = ''.join(mac.split(':'))[:6].upper()
    try:
        with open(lookup_path, 'r') as f:
            for line in f:
                if line.startswith(mac):
                    return line.split()[1].strip()
    except Exception as e:  # pragma: no cover
        return 'Unknown'

def parse_tshark(output):
    results = {'tshark':{}}
    in_block = False
    name = None
    for line in output.split('\n'):
        if line.startswith('==='):
            if in_block:
                in_block = False
                name = None
                continue
            else:
                in_block = True
                continue
        if in_block:
            if not name:
                name = ''.join(line.split(':')).strip()
                results['tshark'][name] = ''
                continue
            elif not line.startswith('Filter:') and line != '':
                results['tshark'][name] += line + '\n'

    for result in results['tshark'].keys():
        if 'Conversations' in result:
            # handle conversation parsing
            conversations = []
            for line in results['tshark'][result].split('\n'):
                if line == '' or line.startswith(' '):
                    # header or padding, dicard
                    continue
                else:
                    src, _, dst, frames_l, bytes_l, frames_r, bytes_r, frames_total, bytes_total, rel_start, duration = line.split()
                    conv = {'Source': src, 'Destination': dst, 'Frames to Source': frames_l, 'Bytes to Source': bytes_l, 'Frames to Destination': frames_r, 'Bytes to Destination': bytes_r, 'Total Frames': frames_total, 'Total Bytes': bytes_total, 'Relative Start': rel_start, 'Duration': duration}
                    if 'Ethernet' in result:
                        conv['Source Vendor'] = get_ether_vendor(src)
                        conv['Destination Vendor'] = get_ether_vendor(dst)
                    conversations.append(conv)
            results['tshark'][result] = conversations
        elif 'Endpoints' in result:
            # handle endpoint parsing
            endpoints = []
            for line in results['tshark'][result].split('\n'):
                if line == '' or line.startswith(' '):
                    # header or padding, dicard
                    continue
                else:
                    # handle endpoint services with ports
                    if result.startswith('UDP') or result.startswith('TCP') or result.startswith('STCP'):
                        endpoint, port, packet_count, byte_count, tx_packets, tx_bytes, rx_packets, rx_bytes = line.split()
                        conv = {'Endpoint': endpoint, 'Port': port, 'Packets': packet_count, 'Bytes': byte_count, 'Tx Packets': tx_packets, 'Tx Bytes': tx_bytes, 'Rx Packets': rx_packets, 'Rx Bytes': rx_bytes}
                        if 'Ethernet' in result:
                            conv['Endpoint Vendor'] = get_ether_vendor(endpoint)
                        endpoints.append(conv)
                    else:
                        endpoint, packet_count, byte_count, tx_packets, tx_bytes, rx_packets, rx_bytes = line.split()
                        conv = {'Endpoint': endpoint, 'Packets': packet_count, 'Bytes': byte_count, 'Tx Packets': tx_packets, 'Tx Bytes': tx_bytes, 'Rx Packets': rx_packets, 'Rx Bytes': rx_bytes}
                        if 'Ethernet' in result:
                            conv['Endpoint Vendor'] = get_ether_vendor(endpoint)
                        endpoints.append(conv)
            results['tshark'][result] = endpoints
        else:
            # handle weird stuff
            for line in results['tshark'][result].split('\n'):
                if line == '' or line.startswith(' '):
                    # header or padding, dicard
                    continue
                else:
                    # handle icmp and icmpv6
                    if result.startswith('ICMP'):
                        if isinstance(results['tshark'][result], str):
                            results['tshark'][result] = {}
                        if line.startswith('Requests') or line.startswith('Minimum'):
                            # header
                            continue
                        else:
                            values = line.split()
                            if len(values) == 4:
                                requests, replies, lost, percent_loss = values
                                results['tshark'][result]['Requests'] = requests
                                results['tshark'][result]['Replies'] = replies
                                results['tshark'][result]['Lost'] = lost
                                results['tshark'][result]['% Loss'] = percent_loss
                            else:
                                minimum, maximum, mean, median, s_deviation, min_frame, max_frame = values
                                results['tshark'][result]['Minimum'] = minimum
                                results['tshark'][result]['Maximum'] = maximum
                                results['tshark'][result]['Mean'] = mean
                                results['tshark'][result]['Median'] = median
                                results['tshark'][result]['Standard Deviation'] = s_deviation
                                results['tshark'][result]['Minimum Frame'] = min_frame
                                results['tshark'][result]['Maximum Frame'] = max_frame
                    elif result.startswith('Protocol'):
                        # TODO
                        continue
                    # handle dns
                    elif result.startswith('DNS'):
                        # TODO
                        continue

    # TODO temporarily remove until parsed
    if 'DNS' in results['tshark']:
        del results['tshark']['DNS']

    # handle protocol hierarchy stats
    a = []
    if 'Protocol Hierarchy Statistics' in results['tshark']:
        a = results['tshark']['Protocol Hierarchy Statistics'].split('\n')
    h = []
    for line in a:
        if line != '':
            name, frame_count, byte_count = line.rsplit(' ', 2)
            name = name.rstrip()
            frame_count = frame_count.split(':')[1]
            byte_count = byte_count.split(':')[1]
            h.append([name, frame_count, byte_count])

    i = 1
    spaces = 0
    if h:
        h[0][0] = '"' + h[0][0].strip()
        while i < len(h):
            prev_spaces = spaces
            spaces = h[i][0].count('  ')
            h[i-1][0] = h[i-1][0].strip() + '":{"Frames": "' + h[i-1][1] + '", "Bytes": "' + h[i-1][2]
            if spaces > prev_spaces:
                h[i-1][0] += '","'
            elif spaces == prev_spaces:
                h[i-1][0] += '"},"'
            else:
                h[i-1][0] += '"}' + ('}'*(prev_spaces-spaces)) + ',"'
            i += 1
        h[i-1][0] = h[i-1][0].strip() + '":{"Frames": "' + h[i-1][1] + '", "Bytes": "' + h[i-1][2] + '"}' + ('}'*(prev_spaces-spaces))

    protocol_str = '{'
    for record in h:
        protocol_str += record[0]
    protocol_str += '}'
    results['tshark']['Protocol Hierarchy Statistics'] = json.loads(protocol_str)

    # add in condensed conversation fields
    results['tshark']['Condensed TCP Conversations'] = condense_conversations(results, 'TCP Conversations')
    results['tshark']['Condensed UDP Conversations'] = condense_conversations(results, 'UDP Conversations')

    print(results)
    return results

def condense_conversations(results, conv_type):
    prot_ip_map = {}
    if conv_type in results['tshark']:
        for conversation in results['tshark'][conv_type]:
            src_ip, src_port = conversation['Source'].rsplit(':', 1)
            dst_ip, dst_port = conversation['Destination'].rsplit(':', 1)
            if not src_ip in prot_ip_map:
                prot_ip_map[src_ip] = {'Destinations': [], 'Source Ports': [], 'Destination Ports': []}
            if not src_port in prot_ip_map[src_ip]['Source Ports']:
                prot_ip_map[src_ip]['Source Ports'].append(src_port)
            if not dst_port in prot_ip_map[src_ip]['Destination Ports']:
                prot_ip_map[src_ip]['Destination Ports'].append(dst_port)
            if not dst_ip in prot_ip_map[src_ip]['Destinations']:
                prot_ip_map[src_ip]['Destinations'].append(dst_ip)
    return prot_ip_map

def run_tshark(path):
    if os.path.getsize(path) == 0:
       print("pcap file empty, no stats")
       return

    results = {}
    output = ''
    try:
        conv_endpoint_types = ['bluetooth', 'eth', 'fc', 'fddi', 'ip', 'ipv6', 'ipx', 'jxta', 'ncp', 'rsvp', 'sctp', 'tcp', 'tr', 'usb', 'udp', 'wlan']
        options = '-n -q -z dns,tree -z io,phs -z icmp,srt -z icmpv6,srt'
        options += ' -z conv,'.join(conv_endpoint_types)
        options += ' -z endpoints,'.join(conv_endpoint_types)
        output = subprocess.check_output(shlex.split(' '.join(['tshark', '-r', path, options])))
        output = output.decode("utf-8")
    except Exception as e:
        print(str(e))

    results = parse_tshark(output)
    return results

if __name__ == '__main__':  # pragma: no cover
    path = get_path()
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if path:
        if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
            try:
                channel = connect_rabbit()
                capinfos_results = run_capinfos(path)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': capinfos_results, 'results': {'tool': 'pcap-stats', 'version': get_version()}}
                send_rabbit_msg(body, channel)
                tshark_results = run_tshark(path)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': tshark_results, 'results': {'tool': 'pcap-stats', 'version': get_version()}}
                send_rabbit_msg(body, channel)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'pcap-stats', 'version': get_version()}}
                send_rabbit_msg(body, channel)
            except Exception as e:
                print(str(e))
        else:
            capinfos_results = run_capinfos(path)
            tshark_results = run_tshark(path)
