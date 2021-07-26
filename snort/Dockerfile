FROM debian:buster-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DAQ_VERSION 2.0.7
ENV SNORT_VERSION 2.9.18
ENV PYTHONPATH=/app/network_tools_lib

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
WORKDIR /opt
RUN wget -qO- https://www.snort.org/downloads/snort/daq-${DAQ_VERSION}.tar.gz | tar -zxv -f - && mv daq-${DAQ_VERSION} daq
WORKDIR /opt/daq
RUN autoreconf -f -i && ./configure && make && make install
WORKDIR /opt
RUN wget -qO- https://www.snort.org/downloads/snort/snort-${SNORT_VERSION}.tar.gz | tar -zxv -f - && mv snort-${SNORT_VERSION} snort
WORKDIR /opt/snort
RUN ./configure --disable-open-appid && make && make install

RUN ldconfig
RUN touch /var/log/snort/alert

WORKDIR /app
COPY /snort/requirements.txt /app/requirements.txt
COPY network_tools_lib /app/network_tools_lib
COPY /snort/snortrules-snapshot-29150/ /etc/snort/
COPY snort/snort.py /app/snort.py
RUN pip3 install -r /app/requirements.txt

RUN python3 /app/snort.py

ENTRYPOINT ["python3", "/app/snort.py"]
CMD [""]
