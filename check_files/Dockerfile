FROM ubuntu:16.04
LABEL maintainer = "dgrossman@iqt.org"

RUN apt-get update; apt-get install -y \
    python3 \
    libyaml-dev \
    python3-dev \
    python-dev \
    python-pip \
    clamav \
    clamav-freshclam

COPY requirements.txt /
RUN find . -name requirements.txt -type f -exec pip install -r {} \;


RUN freshclam

VOLUME /var/lib/clamav

COPY run.py /
COPY run.sh /

ENTRYPOINT ["/run.sh"]
CMD [""]
