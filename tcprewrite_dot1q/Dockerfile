FROM alpine:edge
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add python3 tcpreplay && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

COPY tcprewrite.py tcprewrite.py

ENTRYPOINT ["python3", "tcprewrite.py"]
CMD [""]
