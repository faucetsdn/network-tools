FROM python:3.11-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED 1

COPY rbqwrapper/requirements.txt requirements.txt
RUN apt-get update && apt-get install -y python3-dev
RUN pip3 install -r requirements.txt

COPY rbqwrapper/rbqwrapper.py /rbqwrapper.py
