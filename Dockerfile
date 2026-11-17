FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p instance uploads encrypted_files recycle_bin received_files

# 5000 = web app, 5001 = TCP file-transfer receiver
EXPOSE 5000 5001

# 1 worker on purpose: the TCP receiver and SQLite live in one process.
# Threads handle concurrent web requests.
CMD gunicorn --workers 1 --threads 8 --timeout 120 --bind 0.0.0.0:${PORT} app:app
