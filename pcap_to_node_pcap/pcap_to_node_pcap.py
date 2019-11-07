"""
Plugin that takes pcap files and splits them by server and client
ip addresses

Created on 17 July 2017
@author: Blake Pagon
"""

import argparse
import datetime
import ipaddress
import json
import os
import shlex
import subprocess

import pika


def ipaddress_fields(json_fields):
    ipas = set()
    for _, content in sorted(json_fields.items()):
        try:
            ipa = ipaddress.ip_address(content)
        except ValueError:
            continue
        ipas.add(str(ipa))
    return ipas

def pcap_name_with_layers(pcap_filename, pcap_layers, pcap_suffix):
    pcap_basename = os.path.basename(pcap_filename)
    pcap_basename = pcap_basename.replace(pcap_suffix, '')
    layers_str = '-'.join(pcap_layers)
    layers_pcap_filename = pcap_filename.replace(
        pcap_basename, '-'.join((pcap_basename, layers_str)))
    return layers_pcap_filename

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
            response = subprocess.check_output(shlex.split(' '.join(
                    ['./tshark', '-T', 'json', '-c', str(10), '-r', pcap_filename])))
            pcap_json = json.loads(response.decode("utf-8"))
        except (json.decoder.JSONDecodeError, subprocess.CalledProcessError) as e:
            print(pcap_filename, str(e))
            continue
        pcap_layers = []
        for packet_json in pcap_json:
            try:
                layers_json = packet_json['_source']['layers']
            except KeyError:
                continue
            ipas = set()
            for field in ('ip', 'ip6', 'arp'):
                if field in layers_json:
                    ipas = ipas.union(ipaddress_fields(layers_json[field]))
            packet_layers = list(ipas) + list(layers_json.keys())
            if len(packet_layers) > len(pcap_layers):
                pcap_layers = packet_layers
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

def get_path(paths):
    path = None
    try:
        path = paths[0]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def run_tool(path, protoannotate):
    if os.path.getsize(path) < 100:
       print("pcap file too small, not splitting")
       return

    # need to make directories to store results from pcapsplitter
    base_dir = path.rsplit('/', 1)[0]
    timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
    timestamp = timestamp.replace(':', '_')
    # make directory for tool name recognition of piping to other tools
    output_dir = os.path.join(base_dir, 'pcap-node-splitter' + '-' + timestamp)
    clients_dir = os.path.join(output_dir, 'clients')
    servers_dir = os.path.join(output_dir, 'servers')
    for new_dir in (output_dir, clients_dir, servers_dir):
        try:
            os.mkdir(new_dir)
        except OSError as err:
            print("couldn't make directory %s for output of this tool: %s" % (new_dir, err))

    for tool_cmd in (
            shlex.split("./PcapSplitter -f " + path + " -o " + clients_dir + " -m client-ip"),
            shlex.split("./PcapSplitter -f " + path + " -o " + servers_dir + " -m server-ip")):
        try:
            subprocess.check_call(tool_cmd)
        except Exception as err:
            print("%s: %s" % (tool_cmd, err))

    if protoannotate:
        for pcap_dir in (clients_dir, servers_dir):
            proto_annotate_pcaps(pcap_dir)

    return clients_dir

def parse_args(parser):
    parser.add_argument('--protoannotate', help='use tshark to annotate pcaps with protocol',
        action='store_true', default=True)
    parser.add_argument('paths', nargs='*')
    args = parser.parse_args()
    return args


if __name__ == '__main__':  # pragma: no cover
    args = parse_args(argparse.ArgumentParser())
    path = get_path(args.paths)
    if path:
        result_path = run_tool(path, args.protoannotate)
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
        try:
            channel = connect_rabbit()
            body = {'id': uid, 'type': 'metadata', 'file_path': result_path, 'data': '', 'results': {'tool': 'pcap-splitter', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
