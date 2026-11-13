# Multi-stage extraction of official ProjectDiscovery security binaries
FROM projectdiscovery/subfinder:latest AS subfinder_bin
FROM projectdiscovery/naabu:latest AS naabu_bin
FROM projectdiscovery/httpx:latest AS httpx_bin
FROM projectdiscovery/nuclei:latest AS nuclei_bin

# Multi-stage builder for Assetnote Kiterunner v1.0.2-yemscan1
FROM golang:1.19-alpine@sha256:0ec0646e208ea58e5d29e558e39f2e59fccf39b7bda306cb53bbaff91919eca5 AS kiterunner_builder
WORKDIR /src
COPY kiterunner-src/kiterunner-1.0.2/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod \
    -ldflags "-X 'github.com/assetnote/kiterunner/cmd/kiterunner/cmd.Version=v1.0.2-yemscan1' -X 'github.com/assetnote/kiterunner/cmd/kiterunner/cmd.Commit=e7a7fa6' -X 'github.com/assetnote/kiterunner/cmd/kiterunner/cmd.Date=2021-04-11' -s -w" \
    -o /usr/local/bin/kr ./cmd/kiterunner

# Main Python environment
FROM python:3.11-slim

# Install system dependencies needed for networking, DNS, packet capture, and Alpine-musl binary compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libpcap-dev \
    dnsutils \
    musl \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-compiled, official security tool binaries into PATH
COPY --from=subfinder_bin /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=naabu_bin /usr/local/bin/naabu /usr/local/bin/naabu
COPY --from=httpx_bin /usr/local/bin/httpx /usr/local/bin/httpx
COPY --from=nuclei_bin /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=kiterunner_builder /usr/local/bin/kr /usr/local/bin/kr
RUN ln -s /usr/local/bin/kr /usr/local/bin/kiterunner

# Bundle official verified routes-small.kite wordlist
RUN mkdir -p /opt/kiterunner
COPY routes-small.kite /opt/kiterunner/routes-small.kite

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PREFER_LOCAL_TOOLS=true

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and templates
COPY . .

# Expose web application port
EXPOSE 8000

# Initialize database schema and start server
CMD ["sh", "-c", "python init_db.py && uvicorn main:app --host 0.0.0.0 --port 8000"]
