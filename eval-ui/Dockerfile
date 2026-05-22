# ── Stage 1: Build Angular ────────────────────────────────────────────────────
FROM node:20-alpine AS build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --prefer-offline
COPY frontend/ .
RUN npm run build

# ── Stage 2: FastAPI + static files ──────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/main.py .
COPY --from=build /app/frontend/dist/frontend/browser /app/static
ENV STATIC_DIR=/app/static
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "4200"]
