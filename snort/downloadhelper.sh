#!/bin/bash

# snort.org downloads can fail for multiple reasons; 500s, redirect loops, etc.
# this helper retries downloads verbosely and verifies what was downloaded,
# is a valid tgz.

url=$1
tarfile=$2
retries=5
if [[ "$url" == "" || "$tarfile" == "" ]] ; then
	echo need URL and tarfile
	exit 1
fi

if [[ -f "$tarfile" ]] ; then
	echo $tarfile exists, skipping download
	exit 0
fi

i=0
while [ $i -lt $retries ]; do
	i=$((i+1))
	rm -f $outfile
	# TODO: workaround curl segfault in getaddrinfo() handling redirect under qemu
	finalurl=$(curl -Ls -w %{url_effective} -o /dev/null $url)
	echo final URL: $finalurl
	# TODO: snort binary serving does not work with TLS 1.3
	curl -v "$finalurl" --tlsv1.2 --tls-max 1.2 --output $tarfile --trace -
	tar ztvf $tarfile
	tarstatus=$?
	if [[ -f "$tarfile" && $tarstatus -eq 0 ]] ; then
		echo downloaded $url to $tarfile to $tarfile.
		exit 0
		break
	fi
	echo retrying....
	sleep 60
done

echo failed to download $tarfile.
exit 1
