#!/bin/bash

# smoke test for ncapture worker
# requires tcpdump and tshark to be installed.

URI=lo
IP=127.0.0.1
SIZE=1000
MAXCAPLEN=50

TMPDIR=$(mktemp -d)

docker build -f Dockerfile . -t iqtlabs/ncapture
echo starting ncapture
docker run --privileged --net=host --cap-add=NET_ADMIN -v $TMPDIR:/files -t iqtlabs/ncapture /tmp/run.sh $URI 15 test 1 "host $IP and icmp" "" -d 12 -s 4 -a none -c none -o /files/ || exit 1 &
echo waiting for pcap
PINGS=0
while [ "$(find $TMPDIR -prune -empty)" ] ; do
  ((++PINGS))
  ping -q -n -i 0.1 -s $SIZE -c 10 $IP > /dev/null
  echo -n .$PINGS
  if [ "$PINGS" -gt "60" ] ; then
	  echo timed out waiting for pcap
	  exit 1
  fi
done
echo .got pcap
tcpdump -n -r $TMPDIR/*pcap greater $SIZE > $TMPDIR/greater.txt || exit 1
if [ ! -s $TMPDIR/greater.txt ] ; then
  echo "FAIL: no packets with original size $SIZE"
  exit 1
fi
capinfos -l $TMPDIR/*cap
CAPLEN=$(capinfos -l $TMPDIR/*cap|grep -oE 'Packet size limit:\s+inferred: [0-9]+ bytes'|grep -oE '[0-9]+')
echo caplen: $CAPLEN
if [ "$CAPLEN" == "" ] ; then
  echo "FAIL: capture length not limited"
  exit 1
fi
if [ "$CAPLEN" -gt "$MAXCAPLEN" ] ; then
  echo "FAIL: capture length $CAPLEN over limit (payload not stripped?)"
  exit 1
fi
echo ok

rm -rf $TMPDIR
