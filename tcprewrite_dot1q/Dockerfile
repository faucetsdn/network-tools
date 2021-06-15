FROM alpine:3.14
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

COPY requirements.txt requirements.txt
COPY VERSION VERSION
COPY en10mb.c en10mb.c

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add build-base libtool automake curl autoconf git python3 py3-pip tcpreplay libpcap libpcap-dev && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

RUN pip3 install -r requirements.txt
COPY tcprewrite.py tcprewrite.py

RUN curl -L https://github.com/appneta/tcpreplay/releases/download/v4.3.4/tcpreplay-4.3.4.tar.gz -o tcpreplay-4.3.4.tar.gz
RUN tar -xf tcpreplay-4.3.4.tar.gz
RUN cp en10mb.c tcpreplay-4.3.4/src/tcpedit/plugins/dlt_en10mb/en10mb.c
RUN cd tcpreplay-4.3.4 && \
    if ! ./configure; then cat config.log; exit 1; fi && \
    make && \
    make install

ENTRYPOINT ["python3", "tcprewrite.py"]
CMD [""]
