FROM python:3-alpine
MAINTAINER Peter Bronez <pbronez@iqt.org>

ADD requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
ADD csv_row_broadcast.py csv_row_broadcast.py

ENTRYPOINT ["python3", "csv_row_broadcast.py"]
CMD [""]
