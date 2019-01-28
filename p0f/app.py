import os
import redis
import sys
import time

def run_p0f():
    os.system('/usr/bin/p0f -r ' + sys.argv[1] + ' -o /tmp/p0f_output.txt > /dev/null')
    return

def run_tshark():
    os.system('/usr/bin/tshark -r ' + sys.argv[1] + ' -T fields -e ip.src -e eth.src | sort | uniq > /tmp/tshark_output.txt')
    os.system('/usr/bin/tshark -r ' + sys.argv[1] + ' -T fields -e ip.dst -e eth.dst | sort | uniq >> /tmp/tshark_output.txt')
    return

def parse_output():
    results = {}
    with open('/tmp/p0f_output.txt', 'r') as f:
        for line in f:
            l = " ".join(line.split()[2:])
            l = l.split('|')
            if l[0] == 'mod=syn':
                results[l[1].split('cli=')[1].split('/')[0]] = {'full_os': l[4].split('os=')[1], 'short_os': l[4].split('os=')[1].split()[0]}
    with open('/tmp/tshark_output.txt', 'r') as f:
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
            print('unable to connect to redis because: ' + str(e))
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
            print('unable to store contents of the p0f [ ' + str(results) +
                  ' ] in redis because: ' + str(e))
    return

def main():
    run_p0f()
    run_tshark()
    results = parse_output()
    print(results)
    r = connect()
    save(r, results)
    return

if __name__ == "__main__":  # pragma: no cover
    main()
