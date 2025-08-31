FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    FLASK_APP=app.py \
    UNITY_CA_PORT=5000

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       openssl \
  && rm -rf /var/lib/apt/lists/*

# Create app and data dirs
RUN groupadd -r unity && useradd -r -g unity -m -d /home/unity -s /usr/sbin/nologin unity \
    && mkdir -p /app /data/issued /data/root /data/config /var/log/unity-ca \
    && chown -R unity:unity /app /data /var/log/unity-ca

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy *everything* the app needs (app.py, templates, static, etc.)
COPY --chown=unity:unity . .

USER unity

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--workers", "4", "--timeout", "120"]
