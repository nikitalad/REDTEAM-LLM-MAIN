FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir redis>=5.0.0
COPY server.py .
RUN mkdir -p /app/log
CMD ["python", "server.py"]
