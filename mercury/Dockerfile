FROM python:3.8-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

# Install packages
RUN apt-get update && \
    apt-get install -y gcc libpcap-dev && \
    rm -rf /root/*

COPY . /app
WORKDIR /app

RUN pip3 install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED 1
ENTRYPOINT ["python3", "app.py"]
CMD [""]
