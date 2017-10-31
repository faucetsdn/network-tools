#!/bin/env python
import fnmatch
import os
import sys
import subprocess
import hashlib
import virustotal


def hash_results(p):
    BLOCKSIZE = 65536
    hashers = list()
    hashers.append(('md5', hashlib.md5()))
    hashers.append(('sha1', hashlib.sha1()))

    with open(p, 'rb') as a_file:
        buf = a_file.read(BLOCKSIZE)
        while len(buf) > 0:
            for hasher_name, hasher_func in hashers:
                hasher_func.update(buf)
            buf = a_file.read(BLOCKSIZE)
    ret_val = dict()

    for hasher_name, hasher_func in hashers:
        ret_val[hasher_name] = hasher_func.hexdigest()

    return ret_val


def av_results(p):
    p = subprocess.Popen(['/usr/bin/clamscan', '--no-summary', p],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    a = p.stdout.read()
    return a


def main(virus_key):
    matches = []
    ret_val = dict()

    starting_point = sys.argv[1]

    v = None

    if virus_key != 'UNCONFIGURED':
        v = virustotal.VirusTotal(virus_key)

    # directory
    if os.path.isdir(starting_point):
        for root, dirnames, filenames in os.walk(starting_point):
            for filename in fnmatch.filter(filenames, '*'):
                matches.append(os.path.join(root, filename))
    # single file
    if os.path.isfile(starting_point):
        matches.append(starting_point)

    for match in matches:
        this_dict = {}
        av_result = av_results(match).split(':')[-1].strip()
        hash_result = hash_results(match)
        this_dict['av_results'] = av_result
        this_dict['hash_results'] = hash_result
        if v is not None:
            report = v.get(hash_result['md5'])
            # wait untin the report is generated
            report.join()
            rd = {}
            rd['resource_id'] = report.id
            rd['scan_uid'] = report.scan_id
            rd['permalink'] = report.permalink
            rd['status'] = report.status
            rd['total'] = report.total
            rd['positives'] = report.positives
            md = {}
            for av, malware in report:
                if malware is not None:
                    avd = {}
                    avd['version'] = av[1]
                    avd['update'] = av[2]
                    avd['malware'] = malware
                md[av[0]] = avd
            rd['av'] = md
            this_dict['av_results'] = rd
        else:
            this_dict['av_results'] = None

        ret_val[match] = this_dict
    return ret_val


if __name__ == "__main__":
    virus_key = os.getenv('VIRUS_TOTAL_API_KEY', 'UNCONFIGURED')
    if len(sys.argv) > 1:
        out = main(virus_key)
        retval = {'answer': out}
        print(retval)
    else:
        print("so this is odd...{0}:{1}".format(str(len(sys.argv)), sys.argv))
