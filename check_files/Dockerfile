FROM ubuntu:14.04
MAINTAINER MarvAmBass

RUN apt-get update; apt-get install -y \
    python3 \
    python-pip \
    clamav \
    clamav-freshclam

RUN freshclam

VOLUME /var/lib/clamav

COPY run.py /

CMD freshclam -d; python run.py
