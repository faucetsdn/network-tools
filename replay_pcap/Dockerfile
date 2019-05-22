FROM ubuntu:18.10
LABEL maintainer="Jeff Wang <jwang@iqt.org>"
LABEL vent = "" \
      vent.name = "node pcap" \
      vent.groups = "replay"

RUN apt-get -y update && apt-get install -y --no-install-recommends \
    tcpreplay \
    sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY replay.sh .

ENTRYPOINT ["/replay.sh"]
CMD [""]
