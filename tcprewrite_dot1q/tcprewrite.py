"""
Plugin that takes pcap files and rewrites them without .1Q VLAN tags

Created on 17 May 2018
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

def run_tool(path):
    if os.path.getsize(path) == 0:
       print("pcap file empty, not rewriting")
       return

    # need to make directories to store results from tcprewrite
    base_dir, file_name = path.rsplit('/', 1)
    timestamp = ""
    try:
        timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
        timestamp = timestamp.replace(':', '_')
    except Exception as e:  # pragma: no cover
        print("couldn't create output directory with unique timestamp")
    # make directory for tool name recognition of piping to other tools
    output_dir = os.path.join(base_dir, 'tcprewrite-dot1q' + '-' + timestamp)
    try:
        os.mkdir(output_dir)
    except OSError:  # pragma: no cover
        print("couldn't make directories for output of this tool")
    try:
        subprocess.check_call(shlex.split("tcprewrite --enet-vlan=del --infile=" + path +
                                          " --outfile=" + output_dir + '/' + file_name))
    except Exception as e:
        print(str(e))
    return output_dir + '/' + file_name

if __name__ == '__main__':  # pragma: no cover
    path = get_path()
    if path:
        result_path = run_tool(path)
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']
    if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
        try:
            channel = connect_rabbit()
            body = {'id': uid, 'type': 'metadata', 'file_path': result_path, 'data': '', 'results': {'tool': 'pcap-dot1q', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
