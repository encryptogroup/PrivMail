FROM python:3.11-slim

RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir --no-warn-script-location -r requirements.txt

RUN mkdir mail_data


COPY . .
ENTRYPOINT [ "python", "./smtp_server.py" ]
