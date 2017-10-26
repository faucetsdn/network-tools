FROM ubuntu:16.04
MAINTAINER dgrossman@iqt.org

RUN apt-get update; apt-get install -y \
    python3 \
    libyaml-dev \
    python3-dev \
    python-dev \
    python-pip \
    clamav \
    clamav-freshclam

#RUN freshclam

VOLUME /var/lib/clamav

COPY run.py /

#ENTRYPOINT freshclam -d; python run.py
ENTRYPOINT ["python", "run.py"]
CMD [""]
