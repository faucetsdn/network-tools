FROM alpine:edge
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories

# Install packages
RUN apk update && \
    apk -U upgrade && \
    apk add bash jansson libpcap procps python py-pip p0f && \
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*

COPY . /app
WORKDIR /app

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "app.py"]
CMD [""]
