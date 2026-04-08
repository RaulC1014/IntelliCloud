FROM python:3.12-slim

WORKDIR /app

# System deps needed for pcapy-ng build + runtime sniffing
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install python deps (keep minimal & explicit)
RUN pip install --no-cache-dir --upgrade pip wheel setuptools \
    && pip install --no-cache-dir \
    pcapy-ng \
    scapy \
    psutil \
    requests \
    python-dotenv

COPY ic_agent.py /app/ic_agent.py
# If you store sensor env vars in a file, copy it too (optional)
# COPY .env /app/.env

ENTRYPOINT ["python", "/app/ic_agent.py"]
