FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    RF_HUNTER_CAPTURES=/data/captures/rf-hunter-v2 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    hackrf \
    libhackrf0 \
    rtl-433 \
    multimon-ng \
    bluez \
    libglib2.0-0 \
    libdbus-1-3 \
    iw \
    wireless-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN mkdir -p /data/captures/rf-hunter-v2

EXPOSE 8081

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8081"]
