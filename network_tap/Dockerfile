FROM alpine:3.17
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONPATH=/network-tap/network_tools_lib
ENV PYTHONUNBUFFERED 1

COPY network_tap/ncontrol/requirements.txt requirements.txt
COPY network_tap/healthcheck /healthcheck

RUN apk add --update \
    curl \
    gcc \
    g++ \
    git \
    libev-dev \
    linux-headers \
    musl-dev \
    python3 \
    python3-dev \
    py3-pip \
    && pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r /healthcheck/requirements.txt \
    && apk del \
    gcc \
    g++ \
    git \
    linux-headers \
    musl-dev \
    python3-dev \
    && rm -rf /var/cache/apk/*

# healthcheck
ENV FLASK_APP /healthcheck/hc.py
HEALTHCHECK --interval=15s --timeout=15s \
 CMD curl --silent --fail http://localhost:5000/healthcheck || exit 1

COPY network_tap /network-tap
COPY network_tools_lib /network-tap/network_tools_lib
WORKDIR /network-tap

EXPOSE 8080

CMD (flask run > /dev/null 2>&1) & (python3 ncontrol/ncontrol.py)
