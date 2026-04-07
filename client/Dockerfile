# Slim Python base image for the demo client
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY client.py .

ENTRYPOINT ["python", "client.py"]