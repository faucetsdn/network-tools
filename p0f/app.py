import datetime
import json
import os
import subprocess
import sys
import tempfile
import time

import pika
import redis


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
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'VERSION'), 'r') as f:
        return f.read().strip()

def run_proc(args, shell=False):
    try:
        proc = subprocess.Popen(args, shell=shell, stdout=subprocess.DEVNULL)
        return proc.communicate()
    except FileNotFoundError as e:
        return e

def run_p0f(path, p0f_output):
    args = ['/usr/bin/p0f', '-r', path, '-o', p0f_output]
    return run_proc(args, shell=False)

def run_tshark(path, tshark_output):
    exit_status = []
    args = ' '.join(['/usr/bin/tshark', '-r', path, '-T', 'fields', '-e', 'eth.src', '-e', 'ip.src', '|', 'sort', '|', 'uniq', '>', tshark_output])
    exit_status.append(run_proc(args, shell=True))
    args = ' '.join(['/usr/bin/tshark', '-r', path, '-T', 'fields', '-e', 'ip.src', '-e', 'eth.src', '|', 'sort', '|', 'uniq', '>>', tshark_output])
    exit_status.append(run_proc(args, shell=True))
    return exit_status

def parse_output(p0f_output, tshark_output):
    results = {}
    with open(p0f_output, 'r') as f:
        for line in f:
            l = " ".join(line.split()[2:])
            l = l.split('|')
            if l[0] == 'mod=syn':
                results[l[1].split('cli=')[1].split('/')[0]] = {'full_os': l[4].split('os=')[1], 'short_os': l[4].split('os=')[1].split()[0]}
    with open(tshark_output, 'r') as f:
        for line in f:
            pair = line.split()
            if len(pair) == 2:
                if pair[0] in results:
                    results[pair[0]]['mac'] = pair[1]
    return results

def connect():
    r = None
    try:
        r = redis.StrictRedis(host='redis', port=6379, db=0)
    except Exception as e:  # pragma: no cover
        try:
            r = redis.StrictRedis(host='localhost', port=6379, db=0)
        except Exception as e:  # pragma: no cover
            print('Unable to connect to redis because: ' + str(e))
    return r

def save(r, results):
    timestamp = str(int(time.time()))
    if r:
        try:
            if isinstance(results, list):
                for result in results:
                    for key in result:
                        redis_k = {}
                        for k in result[key]:
                            redis_k[k] = str(result[key][k])
                        r.hmset(key, redis_k)
                        r.hmset('p0f_'+timestamp+'_'+key, redis_k)
                        r.sadd('ip_addresses', key)
                        r.sadd('p0f_timestamps', timestamp)
            elif isinstance(results, dict):
                for key in results:
                    redis_k = {}
                    for k in results[key]:
                        redis_k[k] = str(results[key][k])
                    r.hmset(key, redis_k)
                    r.hmset('p0f_'+timestamp+'_'+key, redis_k)
                    r.sadd('ip_addresses', key)
                    r.sadd('p0f_timestamps', timestamp)
        except Exception as e:  # pragma: no cover
            print('Unable to store contents of p0f: ' + str(results) +
                  ' in redis because: ' + str(e))

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

    with tempfile.TemporaryDirectory() as tempdir:
        p0f_output = os.path.join(tempdir, 'p0f_output.txt')
        tshark_output = os.path.join(tempdir, 'tshark_output.txt')

        for path in pcap_paths:
            run_p0f(path, p0f_output)
            run_tshark(path, tshark_output)
            results = parse_output(p0f_output, tshark_output)
            print(results)

            if os.environ.get('redis', '') == 'true':
                r = connect()
                save(r, results)

            if os.environ.get('rabbit', '') == 'true':
                uid = os.environ.get('id', '')
                version = get_version()
                try:
                    channel = connect_rabbit()
                    body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': results, 'results': {'tool': 'p0f', 'version': version}}
                    send_rabbit_msg(body, channel)
                    if path == pcap_paths[-1]:
                        body = {'id': uid, 'type': 'metadata', 'file_path': path, 'data': '', 'results': {'tool': 'p0f', 'version': version}}
                        send_rabbit_msg(body, channel)
                except Exception as e:
                    print(str(e))


if __name__ == "__main__":  # pragma: no cover
    main()
