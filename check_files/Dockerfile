FROM ubuntu:20.04
LABEL maintainer = "dgrossman@iqt.org"

RUN apt-get update; apt-get install -y --no-install-recommends \
    python3 \
    libyaml-dev \
    python3-dev \
    python-dev \
    python-pip \
    clamav \
    clamav-freshclam \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /
RUN find . -name requirements.txt -type f -exec pip install -r {} \;


RUN freshclam

VOLUME /var/lib/clamav

COPY run.py /
COPY run.sh /

ENTRYPOINT ["/run.sh"]
CMD [""]
