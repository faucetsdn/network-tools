FROM ubuntu:latest
MAINTAINER Jeff Wang <jwang@iqt.org>

LABEL vent = "" \
      vent.name = "node pcap" \
      vent.groups = "replay"

# RUN apk add --update \
    # bash \
    # tcpreplay \
    # && rm -rf /var/cash/apk/*

RUN     apt-get -y update && \
        apt-get -y upgrade

# dependencies
RUN     apt-get -y --force-yes install \
        wget curl build-essential tcpdump tcpreplay

RUN     apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

CMD "./replay.sh $nic $file_path"
