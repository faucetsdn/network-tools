FROM alpine:3.14
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apk add --update \
    python3 \
    tcpdump \
    && rm -rf /var/cache/apk/*

COPY tcpdump_hex_parser.py tcpdump_hex_parser.py

ENTRYPOINT ["python", "tcpdump_hex_parser.py"]
CMD [""]
