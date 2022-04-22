FROM ubuntu:22.04
LABEL maintainer="Jeff Wang <jwang@iqt.org>"

RUN apt-get -y update && apt-get install -y --no-install-recommends \
    tcpreplay \
    sudo \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY replay_pcap/replay.sh /app/replay.sh

ENTRYPOINT ["/app/replay.sh"]
CMD [""]
