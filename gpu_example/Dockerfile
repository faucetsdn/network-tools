FROM nvidia/cuda:8.0-cudnn5-devel-ubuntu16.04
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install numpy tensorflow-gpu

COPY example.py example.py

ENTRYPOINT ["python3", "example.py"]
CMD [""]
