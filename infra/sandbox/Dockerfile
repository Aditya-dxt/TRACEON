FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/traceon

COPY infra/sandbox/requirements.txt /opt/traceon/requirements.txt
RUN pip install --no-cache-dir -r /opt/traceon/requirements.txt \
    && useradd --system --uid 10001 --create-home traceon

COPY scanner/ /opt/traceon/scanner/
COPY infra/sandbox/app.py /opt/traceon/app.py
COPY infra/sandbox/run_scanner.py /opt/traceon/run_scanner.py

USER 10001:10001
EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
