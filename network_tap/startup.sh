#!/bin/sh
gunicorn -b :8080 -k eventlet -w 4 --reload ncontrol.ncontrol
