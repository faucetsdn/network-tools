FROM debian:bullseye-slim AS pcapsplitter

LABEL maintainer = "Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1

WORKDIR /app
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends bash git libpcap-dev make gcc g++ \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN GIT_SSL_NO_VERIFY=true git clone https://github.com/seladb/PcapPlusPlus.git /PcapPlusPlus -b v21.05
WORKDIR /PcapPlusPlus
RUN /bin/bash ./configure-linux.sh --default
WORKDIR /PcapPlusPlus/Examples/PcapSplitter
RUN make

FROM debian:bullseye-slim

ENV PYTHONPATH=/app/network_tools_lib

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-dev python3-pip libpcap0.8 tshark \
  && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY pcap_to_node_pcap/requirements.txt /app/requirements.txt
COPY pcap_to_node_pcap/pcap_to_node_pcap.py /app/pcap_to_node_pcap.py
COPY network_tools_lib /app/network_tools_lib
RUN pip3 install -r /app/requirements.txt
COPY --from=pcapsplitter /PcapPlusPlus/Examples/PcapSplitter/Bin/PcapSplitter /PcapSplitter

RUN python3 /app/pcap_to_node_pcap.py

ENTRYPOINT ["python3", "/app/pcap_to_node_pcap.py"]
CMD [""]
