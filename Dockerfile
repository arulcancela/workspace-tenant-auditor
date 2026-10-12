# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Imagen reproducible para workspace-tenant-auditor.
# Multi-stage: build de dependencias + runtime slim.
# Incluye las librerías de sistema de WeasyPrint (pango, cairo) para el PDF.
# ---------------------------------------------------------------------------

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Dependencias de sistema requeridas por WeasyPrint.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    shared-mime-info \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias primero (mejor caché de capas).
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

# Usuario no-root por seguridad.
RUN useradd --create-home --uid 1000 auditor
USER auditor

# Directorio de trabajo para informes (montable como volumen).
RUN mkdir -p /app/reports
WORKDIR /app

ENTRYPOINT ["tenant-auditor"]
CMD ["audit", "--dry-run", "--output", "/app/reports"]
