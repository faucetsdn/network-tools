#!/bin/bash
# tshark does not respect -s when reading from a capture, so provide
# a wrapper to cut down the capture to IP/header only, which also
# protects tshark's parser.
# bash-ism to retrieve last item in arg list (called by pyshark, is the pcap name)
pcap="${@: -1}"
if [[ ! -f "$pcap" ]] ; then
	echo last arg must exist and be input pcap.
	exit 1
fi
# bash-ism to drop last arg (pcap name)
set -- "${@:1:$#-1}"
# pass remaining pyshark args to tshark, which will end with "-r -".
editcap -F pcap $pcap -s 128 - | tshark $* \-
