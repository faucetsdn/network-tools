FROM alpine:3.12
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt
COPY VERSION VERSION

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add python3 py3-pip tshark && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

RUN pip3 install -r requirements.txt

COPY nmap-mac-prefixes.txt nmap-mac-prefixes.txt
COPY pcap_stats.py pcap_stats.py

ENTRYPOINT ["python3", "pcap_stats.py"]
CMD [""]
