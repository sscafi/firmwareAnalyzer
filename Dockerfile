FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install minimal system dependencies useful for firmware extraction/analysis
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binwalk \
       squashfs-tools \
       p7zip-full \
       unzip \
       libmagic1 \
       libssl-dev \
       build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files and install Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

VOLUME ["/data"]

ENTRYPOINT ["python", "firm_scan.py"]

CMD ["--help"]
