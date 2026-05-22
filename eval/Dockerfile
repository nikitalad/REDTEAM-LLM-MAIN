FROM python:3.11-slim
# Install build dependencies (Rust, Cargo, C compilers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    rustc \
    cargo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "eval/experiments/run_experiment.py"]
