FROM debian:stretch-slim

LABEL maintainer = "Charlie Lewis <clewis@iqt.org>" \
      vent = "" \
      vent.name = "node pcap" \
      vent.groups = "pcap"

ENV DEBIAN_FRONTEND = "noninteractive"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3 \
    python3-pip \
    libpcap-dev \
    make \
    gcc \
    g++ \
    tshark \
    && cp `which tshark` /tshark \
    && GIT_SSL_NO_VERIFY=true git clone https://github.com/seladb/PcapPlusPlus.git /PcapPlusPlus \
    && cd /PcapPlusPlus \
    && /bin/bash ./configure-linux.sh --default \
    && make all \
    && cd / \
    && cp /PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter /PcapSplitter \
    && rm -rf /PcapPlusPlus \
    && apt-get remove --purge --auto-remove -y git make gcc g++ \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /var/cache/apt/archives/*.deb \
        /var/cache/apt/archives/partial/*.deb \
        /var/cache/apt/*.bin \
    && rm -rf /root/.[acpw]*

COPY VERSION VERSION
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY pcap_to_node_pcap.py pcap_to_node_pcap.py

USER nobody

ENTRYPOINT ["python3", "pcap_to_node_pcap.py"]
CMD [""]
