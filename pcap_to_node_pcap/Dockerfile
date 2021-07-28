FROM debian:stretch-slim

LABEL maintainer = "Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app/network_tools_lib

WORKDIR /app
COPY pcap_to_node_pcap/main.cpp /app/main.cpp
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
    && cp main.cpp /PcapPlusPlus/Examples/PcapSplitter/main.cpp \
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

COPY pcap_to_node_pcap/requirements.txt /app/requirements.txt
COPY pcap_to_node_pcap/pcap_to_node_pcap.py /app/pcap_to_node_pcap.py
COPY network_tools_lib /app/network_tools_lib
RUN pip3 install -r /app/requirements.txt

RUN python3 /app/pcap_to_node_pcap.py

ENTRYPOINT ["python3", "/app/pcap_to_node_pcap.py"]
CMD [""]
