FROM alpine:edge
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add bash jansson libpcap procps p0f && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

ADD . /scripts

ENTRYPOINT ["/scripts/run.sh"]
CMD [""]
