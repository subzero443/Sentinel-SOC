# Build the React dashboard (no need to install Docker on your own PC).
FROM node:22-alpine AS dashboard
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN VITE_PUBLIC_DEMO=true npm run build

# Run the API and serve the compiled dashboard at the same URL.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOC_PUBLIC_DEMO=1
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend/ /app/backend/
COPY --from=dashboard /app/frontend/dist/ /app/frontend/dist/
EXPOSE 10000
CMD ["sh", "-c", "exec uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
