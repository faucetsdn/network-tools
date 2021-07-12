FROM python:3.9-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt
ENV PYTHONUNBUFFERED 1

# Install packages
RUN apt-get update && apt-get install -y python3-dev

RUN pip3 install -r requirements.txt

COPY rbqwrapper.py /rbqwrapper.py
