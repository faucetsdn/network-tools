"""
Plugin that takes pcap files and splits them by server and client
ip addresses

Created on 17 July 2017
@author: Blake Pagon
"""

# TODO: https://github.com/PyCQA/bandit/issues/333 for bandit false positive on subprocess.

import argparse
import datetime
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

import pika


def parse_layer_ports(json_fields):
    ports = set()
    for field, content in json_fields.items():
        if field.endswith('port'):
            try:
                port = int(content)
                ports.add(port)
            except ValueError:
                continue
    return ports

def ipaddress_fields(json_fields):
    ipas = set()
    for _, content in sorted(json_fields.items()):
        try:
            ipa = str(ipaddress.ip_address(content))
            ipa = re.sub(r'[^0-9]+', '-', ipa)
        except ValueError:
            continue
        ipas.add(ipa)
    return ipas

def pcap_name_with_layers(pcap_filename, pcap_layers, pcap_suffix):
    pcap_basename = os.path.basename(pcap_filename)
    pcap_basename = pcap_basename.replace(pcap_suffix, '')
    safe_pcap_layers = [
        re.sub(r'[^a-zA-Z0-9\-]+', '', i) for i in pcap_layers]
    layers_str = '-'.join(safe_pcap_layers)
    layers_pcap_filename = pcap_filename.replace(
        pcap_basename, '-'.join((pcap_basename, layers_str)))
    return layers_pcap_filename

def parse_pcap_json_to_layers(pcap_json):
    pcap_layers = []
    for packet_json in pcap_json:
        try:
            layers_json = packet_json['_source']['layers']
        except KeyError:
            continue
        ipas = set()
        ports = set()
        for field in ('ip', 'ipv6', 'arp', 'tcp', 'udp'):
            if field in layers_json:
                json_fields = layers_json[field]
                ipas = ipas.union(ipaddress_fields(json_fields))
                ports = ports.union(parse_layer_ports(json_fields))
        lowest_port = []
        if ports:
            lowest_port = ['port-%u' % min(ports)]
        packet_layers = list(sorted(ipas)) + list(layers_json.keys()) + lowest_port
        if len(packet_layers) > len(pcap_layers):
            pcap_layers = packet_layers
    return pcap_layers

def proto_annotate_pcaps(pcap_dir):
    pcap_suffix = '.pcap'
    try:
        pap_filenames = [
            pcap.path for pcap in os.scandir(pcap_dir)
            if pcap.is_file() and pcap.path.endswith(pcap_suffix)]
    except FileNotFoundError as err:
        print(err)
        return
    for pcap_filename in pap_filenames:
        try:
            response = subprocess.check_output(shlex.split(' '.join( # nosec
                ['./tshark', '-T', 'json', '-c', str(10), '-r', pcap_filename])))
            pcap_json = json.loads(response.decode('utf-8'))
        except (json.decoder.JSONDecodeError, subprocess.CalledProcessError) as e:
            print(pcap_filename, str(e))
            continue
        pcap_layers = parse_pcap_json_to_layers(pcap_json)
        layers_pcap_filename = pcap_name_with_layers(pcap_filename, pcap_layers, pcap_suffix)
        os.rename(pcap_filename, layers_pcap_filename)

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
                          properties=pika.BasicProperties(delivery_mode=2,))
    print(" [X] %s UTC %r %r" % (str(datetime.datetime.utcnow()),
                                 str(msg['id']), str(msg['file_path'])))

def get_version():
    version = ''
    with open('VERSION', 'r') as f:
        for line in f:
            version = line.strip()
    return version

def get_path(paths):
    path = None
    try:
        path = paths[0]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def run_split(in_path, clients_dir, servers_dir):
    for tool_cmd in (
            " ".join(("./PcapSplitter -f", in_path, "-o", clients_dir, "-m client-ip")),
            " ".join(("./PcapSplitter -f", in_path, "-o", servers_dir, "-m server-ip"))):
        try:
            subprocess.check_call(shlex.split(tool_cmd)) # nosec
        except Exception as err:
            print("%s: %s" % (tool_cmd, err))

def run_tool(path, protoannotate):
    if os.path.getsize(path) < 100:
        print("pcap file too small, not splitting")
        return None

    # need to make directories to store results from pcapsplitter
    base_dir = path.rsplit('/', 1)[0]
    timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
    timestamp = timestamp.replace(':', '_')
    output_dir = os.path.join(base_dir, 'pcap-node-splitter' + '-' + timestamp)
    clients_dir = os.path.join(output_dir, 'clients')
    servers_dir = os.path.join(output_dir, 'servers')

    try:
        os.mkdir(output_dir)
        # Ensure file_drop doesn't see pcap before annotation..
        if protoannotate:
            tmp_clients_dir = tempfile.mkdtemp()
            tmp_servers_dir = tempfile.mkdtemp()
            run_split(path, tmp_clients_dir, tmp_servers_dir)
            for tmp_dir, final_dir in (
                    (tmp_clients_dir, clients_dir),
                    (tmp_servers_dir, servers_dir)):
                proto_annotate_pcaps(tmp_dir)
                shutil.copytree(tmp_dir, final_dir)
                shutil.rmtree(tmp_dir)
        else:
            for new_dir in (clients_dir, servers_dir):
                os.mkdir(new_dir)
            run_split(path, clients_dir, servers_dir)
    except Exception as err:
        print(err)

    return clients_dir

def parse_args(parser):
    parser.add_argument(
        '--protoannotate',
        help='use tshark to annotate pcaps with protocol',
        action='store_true',
        default=True)
    parser.add_argument('paths', nargs='*')
    parsed_args = parser.parse_args()
    return parsed_args


if __name__ == '__main__':  # pragma: no cover
    parsed_args = parse_args(argparse.ArgumentParser())
    path = get_path(parsed_args.paths)
    if path:
        result_path = run_tool(path, parsed_args.protoannotate)
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if os.environ.get('rabbit', False) == 'true':
        try:
            channel = connect_rabbit()
            body = {'id': uid, 'type': 'metadata', 'file_path': result_path, 'data': '',
                    'results': {'tool': 'pcap-splitter', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
