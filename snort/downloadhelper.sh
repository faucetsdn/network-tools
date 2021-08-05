#!/bin/bash

# snort.org downloads can fail for multiple reasons; 500s, redirect loops, etc.
# this helper retries downloads verbosely and verifies what was downloaded,
# is a valid tgz.

url=$1
tarfile=$2
retries=5
if [[ "$url" == "" || "$tarfile" == "" ]] ; then
	echo need URL and tarfile
fi

i=0
while [ $i -lt $retries ]; do
	i=$((i+1))
	rm -f $outfile
	curl -Lv $url --output $tarfile
	tar ztvf $tarfile
	tarstatus=$?
	if [[ -f "$tarfile" && $tarstatus -eq 0 ]] ; then
		echo downloaded $url to $tarfile to $tarfile.
		exit 0
		break
	fi
	echo retrying....
	sleep 5
done

echo failed to download $tarfile.
exit 1
