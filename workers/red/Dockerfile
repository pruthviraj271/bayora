FROM python:3.11-slim

RUN groupadd -g 10001 bayorared && \
    useradd -u 10001 -g bayorared -m -s /usr/sbin/nologin bayorared

WORKDIR /app
COPY workers/red/worker.py /app/worker.py
RUN chown -R 10001:10001 /app

USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["python3", "-c", "import time; print('Red worker isolated on red-net ready'); time.sleep(3600)"]
