# Image de base VOLONTAIREMENT ancienne (Python 3.8 en fin de vie) pour le scan Trivy
FROM python:3.8-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000
# Lance le serveur de dev en mode debug (volontairement non securise), en root
CMD ["python", "app.py"]
