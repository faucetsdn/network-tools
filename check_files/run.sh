#!/bin/bash

path=$1
/usr/bin/freshclam -d
python run.py $path
