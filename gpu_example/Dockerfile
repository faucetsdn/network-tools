FROM nvidia/cuda:8.0-cudnn5-devel-ubuntu16.04
MAINTAINER Charlie Lewis <clewis@iqt.org>

RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install numpy tensorflow-gpu

COPY example.py example.py

ENTRYPOINT ["python3", "example.py"]
CMD [""]
