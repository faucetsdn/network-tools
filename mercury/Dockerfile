FROM alpine:3.11
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt

# Install packages
RUN apk add --update \
    gcc \
    linux-headers \
    libffi-dev \
    libpcap-dev \
    musl-dev \
    openssl-dev \
    python3 \
    python3-dev \
    py3-pip \
    && pip3 install --no-cache-dir --upgrade pip==19.1.1 \
    && pip3 install --no-cache-dir -r requirements.txt \
    && apk del \
    gcc \
    libffi-dev \
    libpcap-dev \
    openssl-dev \
    python3-dev \
    && rm -rf /var/cache/apk/*

COPY . /app
WORKDIR /app

ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["python3", "app.py"]
CMD [""]
