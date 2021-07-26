"""
Plugin that takes pcap files and runs them through snort

Created on 6 November 2019
@author: Charlie Lewis
"""

import datetime
import json
import os
import shlex
import subprocess
import sys

import pika
import network_tools_lib

VERSION = network_tools_lib.get_version()


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

def get_path():
    path = None
    try:
        path = sys.argv[1]
    except Exception as e:
        print("No path provided: {0}, quitting".format(str(e)))
    return path

def parse_snort(output):
    lines = output.split('\n')
    keep_lines = False
    good_lines = []
    for line in lines:
        if line.startswith('Commencing packet processing'):
            keep_lines = True
            continue
        if keep_lines:
            good_lines.append(line)

    groups = {}
    i = 0
    title = None
    # remove last two lines for 'snort exiting'
    while i < len(good_lines)-2:
        if good_lines[i].startswith('==='):
            if (good_lines[i+1].startswith('===') or
                good_lines[i+1].startswith('Snort exiting') or
                good_lines[i+1].startswith('Run time for packet') or
                good_lines[i+1].startswith('Memory usage summary') or
                good_lines[i+1].startswith('Packet I/O Totals')):
                i += 1
                continue
            title = good_lines[i+1].strip()
            groups[title] = []
            i += 2
            continue
        if title:
            groups[title].append(good_lines[i])
        i += 1

    return groups

def parse_alerts(alerts):
    alerts = alerts.split('\n\n')
    return {'Alerts': alerts}

def run_tool(path):
    output = ''
    alerts = ''
    try:
        output = subprocess.check_output(shlex.split("snort -c /etc/snort/etc/snort.conf -r " +
                                         path), stderr=subprocess.STDOUT).decode("utf-8")
        alerts = subprocess.check_output(shlex.split("cat /var/log/snort/alert")).decode("utf-8")
    except Exception as e:
        print(str(e))

    output = parse_snort(output)
    alerts = parse_alerts(alerts)
    print(output)
    print(alerts)
    return output, alerts

if __name__ == '__main__':  # pragma: no cover
    path = get_path()
    uid = ''
    if 'id' in os.environ:
        uid = os.environ['id']

    if path:
        results, alerts = run_tool(path)
        if 'rabbit' in os.environ and os.environ['rabbit'] == 'true':
            try:
                channel = connect_rabbit()
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {'tool': 'snort', 'version': VERSION}}
                send_rabbit_msg(body, channel)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': alerts, 'results': {'tool': 'snort', 'version': VERSION}}
                send_rabbit_msg(body, channel)
                body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'snort', 'version': VERSION}}
                send_rabbit_msg(body, channel)
            except Exception as e:
                print(str(e))
