FROM alpine:3.14 as checkout
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apk add --update git
WORKDIR /src
RUN git clone https://github.com/wanduow/wandio.git -b 4.2.3-1 \
    && git clone https://github.com/LibtraceTeam/libtrace.git -b 4.0.16-1 \
    && git clone https://github.com/wanduow/libwdcap.git

FROM alpine:3.14 
COPY --from=checkout /src /src
WORKDIR /src

RUN apk add --update autoconf automake bison build-base flex gcc libtool libpcap-dev libpcap linux-headers openssl-dev musl-dev yaml-dev

WORKDIR /src/wandio
RUN ./bootstrap.sh && ./configure && make && make install 
WORKDIR /src/libtrace
RUN ./bootstrap.sh && ./configure
WORKDIR /src/libtrace/lib
RUN make install
WORKDIR /src/libtrace/libpacketdump
RUN make install
WORKDIR /src/libwdcap
RUN ./bootstrap.sh && ./configure --disable-shared && make && make install
WORKDIR /src/libwdcap/examples 
RUN g++ -fpermissive -o tracecapd tracecapd.c -L/usr/local/lib -Wl,-Bstatic -ltrace -lwdcap -Wl,-Bdynamic -lpcap -lssl -lcrypto -lwandio -lyaml && cp tracecapd /usr/local/bin

WORKDIR /tmp
VOLUME /tmp

COPY network_tap/ncapture/ /tmp
COPY network_tools_lib /tmp/network_tools_lib

RUN apk add --update bash coreutils python3 py3-pip
RUN pip3 install --no-cache-dir -r requirements.txt
RUN ldd /usr/local/bin/tracecapd

ENV PYTHONPATH=/tmp/network_tools_lib
CMD ["/tmp/run.sh"]
