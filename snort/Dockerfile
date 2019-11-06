FROM debian:buster-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DAQ_VERSION 2.0.6
ENV SNORT_VERSION 2.9.15

WORKDIR /opt

RUN mkdir -p /var/log/snort && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    mkdir -p /etc/snort

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-pip \
        wget \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libpcre3-dev \
        libdumbnet-dev \
        zlib1g-dev \
        iptables-dev \
        libnetfilter-queue1 \
        tcpdump \
        unzip && \
        wget https://www.snort.org/downloads/archive/snort/daq-${DAQ_VERSION}.tar.gz \
        && tar xvfz daq-${DAQ_VERSION}.tar.gz \
        && cd daq-${DAQ_VERSION} \
        && ./configure; make; make install && \
        wget https://www.snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz \
        && tar xvfz snort-${SNORT_VERSION}.tar.gz \
        && cd snort-${SNORT_VERSION} \
        && ./configure --disable-open-appid; make; make install && \
        apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /opt/snort-${SNORT_VERSION}.tar.gz /opt/daq-${DAQ_VERSION}.tar.gz

RUN ldconfig
RUN touch /var/log/snort/alert

COPY VERSION VERSION
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY snortrules-snapshot-29150/ /etc/snort/
COPY snort.py snort.py

ENTRYPOINT ["python3", "snort.py"]
CMD [""]
