FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY samples ./samples
COPY scripts ./scripts

ENV DATA_DIR=/data \
    SAMPLES_DIR=/srv/app/samples \
    VAL_PERCENT=20 \
    GAP_SECONDS=60 \
    MAX_UNCOMPRESSED_BYTES=209715200 \
    MAX_ZIP_UPLOAD_BYTES=262144000

VOLUME ["/data"]
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
