FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY backend/app /app/app
COPY scanner/__init__.py scanner/scanner.py scanner/config.py scanner/format_detect.py /app/scanner/
COPY scanner/bom /app/scanner/bom
COPY scanner/dataset_guard /app/scanner/dataset_guard
COPY scanner/explain /app/scanner/explain
COPY scanner/pickle_scan /app/scanner/pickle_scan
COPY scanner/safetensors_verify /app/scanner/safetensors_verify
COPY scanner/weights /app/scanner/weights
RUN useradd --create-home --uid 10001 traceon
USER 10001

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
