FROM python:3.9-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt
COPY VERSION VERSION
ENV PYTHONUNBUFFERED 1

# Install packages
RUN apt-get update && \
    apt-get install -y \
    python3-enchant tshark whois && \
    rm -rf /root/*

RUN pip3 install -r requirements.txt

COPY nmap-mac-prefixes.txt nmap-mac-prefixes.txt
COPY asn.sh asn.sh
COPY pcap_stats.py pcap_stats.py

ENTRYPOINT ["python3", "pcap_stats.py"]
CMD [""]
