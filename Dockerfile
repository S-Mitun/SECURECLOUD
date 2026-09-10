# ==============================================================================
# SecureCloud - Production Multi-Stage Dockerfile
# Serves both React Vite Frontend & FastAPI Backend in a Unified Container
# ==============================================================================

# --- Stage 1: Build Frontend Assets ---
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# --- Stage 2: Runtime Backend & Application ---
FROM python:3.11-slim AS runtime
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt

# Copy Backend, ML, Scripts, complete database, and file storage
COPY backend/ ./backend/
COPY ml/ ./ml/
COPY scripts/ ./scripts/
COPY securecloud.db ./securecloud.db
COPY storage/ ./storage/

# Copy compiled frontend from Stage 1 into the location expected by FastAPI
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Ensure storage directories exist
RUN mkdir -p storage/uploads storage/quarantine storage/confidential storage/recycle_bin storage/temp

# Default environment configuration
ENV PYTHONUNBUFFERED=1
ENV ENVIRONMENT=production
ENV HOST=0.0.0.0
ENV PORT=8000

# Expose container port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Start the unified SecureCloud server
CMD ["python", "backend/run.py"]
