FROM python:3.11-slim

# Add curl so shell_exec attacks can actually exfiltrate
RUN apt-get update && apt-get install -y curl git --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py .
COPY tools.py .
EXPOSE 8000
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000"]