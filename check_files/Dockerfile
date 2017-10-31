FROM ubuntu:16.04
LABEL maintainer="dgrossman@iqt.org"

RUN apt-get update; apt-get install -y \
    python3 \
    libyaml-dev \
    python3-dev \
    python-dev \
    python-pip \
    clamav \
    clamav-freshclam

RUN freshclam

VOLUME /var/lib/clamav

COPY run.py /
COPY run.sh /

ENTRYPOINT ["/run.sh"]
CMD [""]
