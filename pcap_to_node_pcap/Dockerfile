FROM ubuntu:16.04

LABEL maintainer = "Blake Pagon <bpagon@iqt.org>" \
      vent = "" \
      vent.name = "node pcap" \
      vent.groups = "pcap"

RUN apt-get update && apt-get install --no-install-recommends -y git \
    python \
    python-pip \
    libpcap-dev \
    make \
    gcc \
    g++

RUN git clone https://github.com/seladb/PcapPlusPlus.git /PcapPlusPlus

WORKDIR /PcapPlusPlus

RUN ["/bin/bash", "./configure-linux.sh", "--default"]

RUN make all

WORKDIR /

COPY pcap_to_node_pcap.py pcap_to_node_pcap.py

ENTRYPOINT ["python", "pcap_to_node_pcap.py"]
CMD [""]
