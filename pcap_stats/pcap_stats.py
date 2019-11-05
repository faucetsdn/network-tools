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
                    conversations.append({'Source':src, 'Destination': dst, 'Frames to source': frames_l, 'Bytes to source': bytes_l, 'Frames to destination': frames_r, 'Bytes to destionation': bytes_r, 'Total frames': frames_total, 'Bytes total': bytes_total, 'Relative start': rel_start, 'Duration': duration})
            results['tshark'][result] = conversations
        elif 'Endpoints' in result:
            # handle endpoint parsing
            continue
        else:
            # handle weird stuff
            continue

    return results

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
    if path:
        capinfos_results = run_capinfos(path)
        tshark_results = run_tshark(path)
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
        try:
            channel = connect_rabbit()
            body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': capinfos_results, 'results': {'tool': 'pcap_stats', 'version': get_version()}}
            send_rabbit_msg(body, channel)
            body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': tshark_results, 'results': {'tool': 'pcap_stats', 'version': get_version()}}
            send_rabbit_msg(body, channel)
            body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'pcap_stats', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
