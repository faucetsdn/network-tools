FROM ubuntu:latest
MAINTAINER Jeff Wang <jwang@iqt.org>

LABEL vent = "" \
      vent.name = "node pcap" \
      vent.groups = "replay"

RUN     apt-get -y update && \
        apt-get -y upgrade

RUN     apt-get -y --force-yes install \
        tcpreplay

RUN     apt-get clean && \
        rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/replay.sh"]
CMD [""]
