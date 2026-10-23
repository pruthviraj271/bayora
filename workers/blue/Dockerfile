FROM python:3.11-slim

RUN groupadd -g 10002 bayorablue && \
    useradd -u 10002 -g bayorablue -m -s /usr/sbin/nologin bayorablue

WORKDIR /app
COPY workers/blue/worker.py /app/worker.py
RUN chown -R 10002:10002 /app

USER 10002:10002
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["python3", "-c", "import time; print('Blue worker isolated on blue-net ready'); time.sleep(3600)"]
