FROM python:3.11-slim

RUN useradd --create-home appuser
WORKDIR /home/appuser
USER appuser

COPY requirements.txt ./
RUN pip install --no-cache-dir --no-warn-script-location -r requirements.txt


COPY . .
ENTRYPOINT [ "python", "./sender_client_proxy.py" ]
