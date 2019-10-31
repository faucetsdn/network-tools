FROM ubuntu:20.04
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    python-crypto \
    python-dpkt \
    python-ipy \
    python-pip \
    python-pypcap \
    wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install pygeoip

RUN git clone https://github.com/USArmyResearchLab/Dshell.git

# install geo
WORKDIR /Dshell/share/GeoIP
RUN wget http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz
RUN wget http://download.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz
RUN gunzip ./*.gz

WORKDIR /Dshell
RUN make

COPY . /dshell_netflow
WORKDIR /dshell_netflow

ENTRYPOINT ["python", "dshell_netflow_parser.py"]
CMD [""]
