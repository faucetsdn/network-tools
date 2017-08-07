FROM ubuntu:latest
MAINTAINER Jeff Wang <jwang@iqt.org>

LABEL vent = "" \
      vent.name = "node pcap" \
      vent.groups = "replay"

RUN     apt-get -y update && \
        apt-get -y upgrade

RUN     apt-get -y --force-yes install \
        tcpdump \ 
        tcpreplay \
        sudo

RUN     apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD     replay.sh .

ENTRYPOINT ["/replay.sh"]
CMD [""]
