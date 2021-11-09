FROM iqtlabs/rbqwrapper:v0.11.30
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND noninteractive
ENV PYTHONUNBUFFERED 1
ENV PYTHONPATH=/app/network_tools_lib

# Install packages
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libxml2-dev libxslt-dev python3-dev tshark p0f zlib1g-dev && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

WORKDIR /app
COPY p0f/ /app
COPY network_tools_lib /app/network_tools_lib
RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/rbqwrapper.py", "python3", "/app/app.py"]
