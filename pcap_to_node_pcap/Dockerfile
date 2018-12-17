FROM ubuntu:18.04

LABEL maintainer = "Blake Pagon <bpagon@iqt.org>" \
      vent = "" \
      vent.name = "node pcap" \
      vent.groups = "pcap"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python \
    python-pip \
    libpcap-dev \
    make \
    gcc \
    g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/seladb/PcapPlusPlus.git /PcapPlusPlus

WORKDIR /PcapPlusPlus

RUN ["/bin/bash", "./configure-linux.sh", "--default"]

RUN make all

WORKDIR /

COPY pcap_to_node_pcap.py pcap_to_node_pcap.py

ENTRYPOINT ["python", "pcap_to_node_pcap.py"]
CMD [""]
