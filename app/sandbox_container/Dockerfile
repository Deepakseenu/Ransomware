# Base image
FROM ubuntu:22.04

# --- System setup ---
ENV DEBIAN_FRONTEND=noninteractive

# Update and install dependencies
RUN apt update && apt install -y \
    python3 python3-pip \
    clamav clamav-daemon \
    yara \
    curl vim \
    && rm -rf /var/lib/apt/lists/*

# --- Setup directories ---
RUN mkdir -p /analysis/files /opt/honeypot_tools/logs

# Copy analyzer script
COPY container_analyzer.py /analysis/container_analyzer.py

# Set working directory
WORKDIR /analysis

# --- Update ClamAV definitions automatically ---
RUN freshclam || true

# --- Permissions ---
RUN chmod -R 755 /analysis && chmod -R 755 /opt/honeypot_tools

# --- Optional: Install Python libraries if needed in future ---
RUN pip install --no-cache-dir pandas requests

# --- Default command ---
CMD ["python3", "container_analyzer.py"]
