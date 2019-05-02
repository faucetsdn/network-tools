FROM alpine:edge
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add bash jansson libpcap procps python3 py3-pip p0f tshark && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*
RUN pip3 install -U pip==19.1

COPY . /app
WORKDIR /app

RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python3", "app.py"]
CMD [""]
