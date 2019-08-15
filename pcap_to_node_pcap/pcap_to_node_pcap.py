"""
Plugin that takes pcap files and splits them by server and client
ip addresses

Created on 17 July 2017
@author: Blake Pagon
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
    if os.path.getsize(path) < 100:
       print("pcap file too small, not splitting")
       return

    # need to make directories to store results from pcapsplitter
    base_dir = path.rsplit('/', 1)[0]
    timestamp = ""
    try:
        timestamp = '-'.join(str(datetime.datetime.now()).split(' ')) + '-UTC'
        timestamp = timestamp.replace(':', '_')
    except Exception as e:  # pragma: no cover
        print("couldn't create output directory with unique timestamp")
    # make directory for tool name recognition of piping to other tools
    output_dir = os.path.join(base_dir, 'pcap-node-splitter' + '-' + timestamp)
    try:
        os.mkdir(output_dir)
        os.mkdir(output_dir + '/clients')
        os.mkdir(output_dir + '/servers')
    except OSError:  # pragma: no cover
        print("couldn't make directories for output of this tool")
    try:
        subprocess.check_call(shlex.split("./PcapSplitter -f " +
                                          path + " -o " + output_dir + '/clients' + " -m client-ip"))

        subprocess.check_call(shlex.split("./PcapSplitter -f " +
                                          path + " -o " + output_dir + '/servers' + " -m server-ip"))
    except Exception as e:
        print(str(e))
    return output_dir + '/clients'

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
            body = {'id': uid, 'type': 'metadata', 'file_path': result_path, 'data': '', 'results': {'tool': 'pcap-splitter', 'version': get_version()}}
            send_rabbit_msg(body, channel)
        except Exception as e:
            print(str(e))
