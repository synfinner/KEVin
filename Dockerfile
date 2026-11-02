# Python 3.12.16 security release. This multi-arch index digest is the
# python:3.12-slim image published 2026-11-02 (Debian trixie).
FROM python:3.12.16-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

# Set environment variables to prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# Dockerfile
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0

# Install necessary system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy and install dependencies. Upgrade pip first so the image no longer
# keeps the pip 25.0.1 installer, whose vendored CA bundle predates the
# emSign distrust.
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade "pip==26.2.2" \
    && python -m pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the original port (unchanged)
EXPOSE 8444

# Command to run Gunicorn with flask
CMD ["gunicorn", "--bind", "0.0.0.0:8444", "--workers", "4", "--worker-class", "gevent", "--timeout", "30", "--max-requests", "1000", "--max-requests-jitter", "50", "kevin:app"]