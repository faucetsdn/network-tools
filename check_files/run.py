#!/bin/env python
import fnmatch
import os
import subprocess


def av_results(p):
    p = subprocess.Popen(['clamscan','--no-summary',p],stdout=subprocess.PIPE)
    a = p.stdout.read()
    return a
    

def main():
    matches = []
    for root, dirnames, filenames in os.walk('/data'):
       for filename in fnmatch.filter(filenames, '*'):
            matches.append(os.path.join(root, filename))
    print(matches)
    for match in matches:
        av_result = av_results(match)
        print(match, av_result)



if __name__ == "__main__":
    print("winning")
    main()
