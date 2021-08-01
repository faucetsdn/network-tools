FROM alpine:3.14 as checkout
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apk add --update git
WORKDIR /src
RUN git clone https://github.com/wanduow/wandio.git -b 4.2.3-1 \
    && git clone https://github.com/LibtraceTeam/libtrace.git -b 4.0.16-1 \
    && git clone https://github.com/openssl/openssl -b OpenSSL_1_0_2s \
    && git clone https://github.com/wanduow/libwdcap.git

FROM alpine:3.14 as builder
COPY --from=checkout /src /src
WORKDIR /src

# TODO: libwdcap currently requires openssl 1.0.2
RUN apk add --update autoconf automake coreutils bison build-base flex gcc libtool libpcap-dev libpcap linux-headers musl-dev yaml-dev \
    && cd /src/openssl \
    && ./config --prefix=/usr/local --openssldir=/usr/local/openssl \
    && make && make install_sw \
    && cd /src/wandio \
    && ./bootstrap.sh \
    && ./configure \
    && make && make install \
    && cd /src/libtrace \
    && ./bootstrap.sh \
    && ./configure \
    && make && make install \
    && cd /src/libwdcap \
    && ./bootstrap.sh \
    && ./configure --disable-shared \
    && make && make install \
    && cd examples \
    && g++ -fpermissive -o tracecapd tracecapd.c -L/usr/local/lib -Wl,-Bstatic -ltrace -lwdcap -Wl,-Bdynamic -lpcap -lssl -lcrypto -lwandio -lyaml \
    && cp tracecapd /usr/local/bin

FROM alpine:3.14

WORKDIR /tmp
VOLUME /tmp
COPY network_tap/ncapture/ /tmp
COPY network_tools_lib /tmp/network_tools_lib
COPY --from=builder /etc/ssl /etc/ssl
COPY --from=builder /usr/local/openssl /usr/local/openssl
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin/tracecapd /usr/local/bin/tracecapd

RUN apk add --update bash coreutils libstdc++ libgcc libpcap yaml python3 py3-pip
RUN pip3 install --no-cache-dir -r requirements.txt
RUN ldd /usr/local/bin/tracecapd

ENV PYTHONPATH=/tmp/network_tools_lib
CMD ["/tmp/run.sh"]
