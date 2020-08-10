FROM debian:buster-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DAQ_VERSION 2.0.7
ENV SNORT_VERSION 2.9.16.1

WORKDIR /opt

RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort

RUN apt-get update && \
    apt-get install -y \
        autoconf \
        python3 \
        python3-pip \
        wget \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        libtool \
        zlib1g-dev \
        iptables-dev \
        libnetfilter-queue1 \
        tcpdump \
        unzip && \
        apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
RUN wget https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz \
        && tar xvfz daq-${DAQ_VERSION}.tar.gz \
        && cd daq-${DAQ_VERSION} \
        && autoreconf -f -i \
        && ./configure; make; make install \
        && rm -rf /opt/daq-${DAQ_VERSION}.tar.gz
RUN wget https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz \
        && tar xvfz snort-${SNORT_VERSION}.tar.gz \
        && cd snort-${SNORT_VERSION} \
        && ./configure --disable-open-appid; make; make install \
        && rm -rf /opt/snort-${SNORT_VERSION}.tar.gz

RUN ldconfig
RUN touch /var/log/snort/alert

COPY VERSION VERSION
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY snortrules-snapshot-29150/ /etc/snort/
COPY snort.py snort.py

ENTRYPOINT ["python3", "snort.py"]
CMD [""]
