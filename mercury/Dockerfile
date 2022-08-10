# TODO: requires python3.8
FROM alpine:3.16
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app/network_tools_lib

WORKDIR /app
COPY mercury/requirements.txt /app/requirements.txt
RUN apk add --update \
    cargo \
    gcc \
    linux-headers \
    libffi-dev \
    libpcap-dev \
    musl-dev \
    openssl-dev \
    python3 \
    python3-dev \
    py3-pip \
    && pip3 install --no-cache-dir -r /app/requirements.txt \
    && apk del \
    cargo \
    gcc \
    libffi-dev \
    openssl-dev \
    python3-dev \
    && rm -rf /var/cache/apk/*

COPY mercury/ /app
COPY network_tools_lib/ /app/network_tools_lib
RUN python3 /app/app.py

ENTRYPOINT ["python3", "/app/app.py"]
CMD [""]
