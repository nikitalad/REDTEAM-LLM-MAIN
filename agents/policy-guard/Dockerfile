FROM python:3.11-slim

# curl + git present intentionally — same attack surface as react/coder reviewer agents
RUN apt-get update && apt-get install -y curl git --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py tools.py guardrails.py ./
EXPOSE 8000
CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8000"]
