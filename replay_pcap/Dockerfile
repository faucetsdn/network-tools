FROM ubuntu:latest
MAINTAINER Jeff Wang <jwang@iqt.org>

LABEL vent = "" \
      vent.name = "node pcap" \
      vent.groups = "replay"

RUN     apt-get -y update && \
        apt-get -y upgrade

RUN     apt-get -y --force-yes install \
        wget curl tcpreplay

RUN     apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

CMD "./replay.sh $nic $file_path"
