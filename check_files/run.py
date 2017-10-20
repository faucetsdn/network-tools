#!/bin/env python
import fnmatch
import os
import subprocess
import hashlib


def hash_results(p):
    BLOCKSIZE = 65536
    hashers = list()
    hashers.append(('md5',hashlib.md5()))
    hashers.append(('sha1',hashlib.sha1()))
    
    with open(p,'rb') as a_file:
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
    p = subprocess.Popen(['clamscan','--no-summary',p],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    a = p.stdout.read()
    return a
    

def main():
    matches = []
    ret_val = dict()
    for root, dirnames, filenames in os.walk('/data'):
       for filename in fnmatch.filter(filenames, '*'):
            matches.append(os.path.join(root, filename))
    for match in matches:
        this_dict = {}
        av_result = av_results(match).split(':')[-1].strip()
        hash_result = hash_results(match)
        this_dict['av_results'] = av_result
        this_dict['hash_results'] = hash_result
        ret_val[match] = this_dict
    return ret_val
     
        
if __name__ == "__main__":
    out = main()
    print(out)
