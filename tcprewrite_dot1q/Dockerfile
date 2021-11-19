FROM alpine:3.15
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app/network_tools_lib

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

WORKDIR /app
COPY tcprewrite_dot1q/requirements.txt /app/requirements.txt
COPY tcprewrite_dot1q/en10mb.c /app/en10mb.c

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add build-base libtool automake curl autoconf git python3 py3-pip tcpreplay libpcap libpcap-dev && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

RUN pip3 install -r /app/requirements.txt
COPY tcprewrite_dot1q/tcprewrite.py /app/tcprewrite.py
COPY network_tools_lib /app/network_tools_lib

RUN curl -Ls https://github.com/appneta/tcpreplay/releases/download/v4.3.4/tcpreplay-4.3.4.tar.gz | tar zxvf -
RUN cp /app/en10mb.c tcpreplay-4.3.4/src/tcpedit/plugins/dlt_en10mb/en10mb.c
WORKDIR /app/tcpreplay-4.3.4
RUN if ! ./configure; then cat config.log; exit 1; fi && \
    make && \
    make install
WORKDIR /app
RUN python3 /app/tcprewrite.py

ENTRYPOINT ["python3", "/app/tcprewrite.py"]
CMD [""]
