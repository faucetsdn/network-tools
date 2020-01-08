FROM python:3.8-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

# Install packages
RUN apt-get update && \
    apt-get install -y gcc libpcap-dev && \
    rm -rf /root/*

COPY . /app
WORKDIR /app

RUN pip3 install --no-cache-dir -r requirements.txt

# FIX pmercury unicode error
RUN sed -i "367 a \ \ \ \ \ \ \ \ \ \ \ \ if 'http' in flow_repr and 'user_agent' in flow_repr['http']:" /usr/local/bin/pmercury
RUN sed -i "368 a \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ \ flow_repr['http']['user_agent'] = flow_repr['http']['user_agent'].decode('utf-8', 'ignore')" /usr/local/bin/pmercury

ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python3", "app.py"]
CMD [""]
