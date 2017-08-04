FROM ubuntu:16.04

RUN     apt-get -y update && \
        apt-get -y upgrade

RUN     apt-get -y --force-yes install \
        tcpreplay

RUN     apt-get clean

WORKDIR /replaypcap

CMD [""]
