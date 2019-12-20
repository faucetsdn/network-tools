FROM alpine:3.11
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

# Install packages
RUN apk update && \
    apk add bash jansson libpcap gcc libxml2-dev libxslt-dev linux-headers musl-dev procps python3 python3-dev py3-pip tshark && \
    apk add p0f --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

COPY . /app
WORKDIR /app

RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "app.py"]
CMD [""]
