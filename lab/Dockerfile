FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
# tcpdump/libpcap: cho Scapy biên dịch bộ lọc BPF; iptables: cho responder chặn IP
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump iptables \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
