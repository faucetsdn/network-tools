FROM nvidia/cuda:10.2-cudnn7-devel-ubuntu18.04
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip python3-setuptools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install numpy tensorflow-gpu

COPY example.py example.py

ENTRYPOINT ["python3", "example.py"]
CMD [""]
