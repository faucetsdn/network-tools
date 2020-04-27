import datetime
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pika
import pyshark


def connect_rabbit(host='messenger', port=5672, queue='task_queue'):
    params = pika.ConnectionParameters(host=host, port=port)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.queue_declare(queue=queue, durable=True)
    return (connection, channel)

def send_rabbit_msg(msg, channel, exchange='', routing_key='task_queue'):
    channel.basic_publish(exchange=exchange,
                          routing_key=routing_key,
                          body=json.dumps(msg),
                          properties=pika.BasicProperties(delivery_mode=2))
    print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))

def get_version():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'VERSION'), 'r') as f:
        return f.read().strip()

def run_proc(args, output=subprocess.DEVNULL):
    proc = subprocess.Popen(args, stdout=output)
    return proc.communicate()

def run_p0f(path):
    with tempfile.TemporaryDirectory() as tempdir:
        p0f = shutil.which('p0f')
        # p0f not in PATH, default to alpine location.
        if p0f is None:
            p0f = '/usr/bin/p0f'
        p0f_output = os.path.join(tempdir, 'p0f_output.txt')
        args = [p0f, '-r', path, '-o', p0f_output]
        run_proc(args)
        with open(p0f_output, 'r') as f:
            return f.read()

def parse_ip(packet):
    for ip_type in ('ip', 'ipv6'):
        try:
            ip_fields = getattr(packet, ip_type)
        except AttributeError:
            continue
        src_ip_address = getattr(ip_fields, '%s.src' % ip_type)
        dst_ip_address = getattr(ip_fields, '%s.dst' % ip_type)
        return (src_ip_address, dst_ip_address)
    return (None, None)

def parse_eth(packet):
    src_eth_address = packet.eth.src
    dst_eth_address = packet.eth.dst
    return (src_eth_address, dst_eth_address)

def run_tshark(path):
    addresses = set()
    with pyshark.FileCapture(path, include_raw=False, keep_packets=False,
                             custom_parameters=['-o', 'tcp.desegment_tcp_streams:false']) as cap:
        for packet in cap:
            src_eth_address, dst_eth_address = parse_eth(packet)
            src_address, dst_address = parse_ip(packet)
            if src_eth_address and src_address:
                addresses.add((src_address, src_eth_address))
            if dst_eth_address and dst_address:
                addresses.add((dst_address, dst_eth_address))
    return addresses

def parse_output(p0f_output, addresses):
    results = {}
    for p0f_line in p0f_output.splitlines():
        fields = p0f_line.split('|')
        fields_data = {}
        for field in fields[1:]:
            k, v = field.split('=', 1)
            fields_data[k] = v
        subj = fields_data.get('subj', None)
        host = str(ipaddress.ip_address(fields_data[subj].split('/')[0]))
        host_results = {}
        if 'os' in fields_data:
            full_os = fields_data['os']
            if not full_os.startswith('?'):
                short_os = full_os.split(' ')[0]
                host_results.update({
                    'full_os': full_os,
                    'short_os': short_os})
        for host_field in ('link', 'raw_mtu'):
            host_value = fields_data.get(host_field, None)
            if host_value is not None and not host_value.startswith('?'):
                host_results.update({host_field: host_value})
        if host_results:
            if host not in results:
                results[host] = {}
            results[host].update(host_results)
    for address, eth_address in addresses:
        if address in results:
            results[address].update({'mac': eth_address})
    return results

def ispcap(pathfile):
    for ext in ('pcap', 'pcapng', 'dump', 'capture'):
        if pathfile.endswith(''.join(('.', ext))):
            return True
    return False

def main():
    pcap_paths = []
    path = sys.argv[1]
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for pathfile in files:
                if ispcap(pathfile):
                    pcap_paths.append(os.path.join(root, pathfile))
    else:
        pcap_paths.append(path)


    for path in pcap_paths:
        p0f_output = run_p0f(path)
        addresses = run_tshark(path)
        results = parse_output(p0f_output, addresses)
        print(results)

        if os.environ.get('rabbit', '') == 'true':
            uid = os.environ.get('id', '')
            version = get_version()
            queue = os.getenv('RABBIT_QUEUE_NAME', 'task_queue')
            routing_key = os.getenv('RABBIT_ROUTING_KEY', 'task_queue')
            exchange = os.getenv('RABBIT_EXCHANGE', 'task_queue')
            try:
                connection, channel = connect_rabbit(queue=queue)
                body = {
                    'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {
                        'tool': 'p0f', 'version': version}}
                send_rabbit_msg(body, channel, exchange=exchange, routing_key=routing_key)
                if path == pcap_paths[-1]:
                    body = {
                        'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {
                            'tool': 'p0f', 'version': version}}
                    send_rabbit_msg(body, channel)
                connection.close()
            except Exception as e:
                print(str(e))


if __name__ == "__main__":  # pragma: no cover
    main()
