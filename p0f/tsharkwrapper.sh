#!/bin/bash
# tshark does not respect -s when reading from a capture, so provide
# a wrapper to cut down the capture to IP/header only, which also
# protects tshark's parser.
pcap="${@: -1}"
if [[ ! -f "$pcap" ]] ; then
	echo last arg must exist and be input pcap.
	exit 1
fi
set -- "${@:1:$#-1}"
editcap -F pcap $pcap -s 128 - | tshark $* \-
