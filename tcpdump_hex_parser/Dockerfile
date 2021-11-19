FROM alpine:3.15
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apk add --update \
    python3 \
    tcpdump \
    && rm -rf /var/cache/apk/*

WORKDIR /app
COPY tcpdump_hex_parser/tcpdump_hex_parser.py /app/tcpdump_hex_parser.py
RUN python3 /app/tcpdump_hex_parser.py

ENTRYPOINT ["python3", "/app/tcpdump_hex_parser.py"]
CMD [""]
