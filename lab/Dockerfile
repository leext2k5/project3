FROM python:3.13-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
# tcpdump/libpcap: cần cho Scapy biên dịch bộ lọc BPF khi sniff
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
