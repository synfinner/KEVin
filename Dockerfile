# Use the official Python-slim image as the base image
FROM python:3.12-slim

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

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the original port (unchanged)
EXPOSE 8444

# Command to run Gunicorn with flask
CMD ["gunicorn", "--bind", "0.0.0.0:8444", "--workers", "4", "--worker-class", "gevent", "--timeout", "30", "--max-requests", "1000", "--max-requests-jitter", "50", "kevin:app"]