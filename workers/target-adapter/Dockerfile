FROM python:3.11-slim

RUN groupadd -g 10003 bayoratarget && \
    useradd -u 10003 -g bayoratarget -m -s /usr/sbin/nologin bayoratarget

WORKDIR /app
COPY backend /app/backend
COPY workers/target-adapter/adapter_service.py /app/adapter_service.py
RUN chown -R 10003:10003 /app

USER 10003:10003
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

CMD ["python3", "-c", "import time; print('Target LLM Mock Adapter isolated on control-net ready'); time.sleep(3600)"]
