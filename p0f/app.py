import os
import redis
import sys

def run_p0f():
    os.system('/usr/bin/p0f -r ' + sys.argv[1] + ' -o /tmp/output.txt > /dev/null')
    return

def parse_output():
    results = {}
    with open('/tmp/output.txt', 'r') as f:
        for line in f:
            l = " ".join(line.split()[2:])
            l = l.split('|')
            if l[0] == 'mod=syn':
                results[l[1].split('cli=')[1].split('/')[0]] = {'full_os': l[4].split('os=')[1], 'short_os': l[4].split('os=')[1].split()[0]}
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
    if r:
        try:
            for result in results:
                for key in result:
                    r.hmset(key, result[key])
                    r.sadd('ip_addresses', key)
        except Exception as e:  # pragma: no cover
            print('unable to store contents of the p0f [ ' + str(results) +
                  ' ] in redis because: ' + str(e))
    return

def main():
    run_p0f()
    results = parse_output()
    print(results)
    r = connect()
    save(r, results)
    return

if __name__ == "__main__":
    main()
