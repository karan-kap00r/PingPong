# Use Python 3.11 as the base image
FROM --platform=linux/amd64 python:3.11-slim

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose the application port
EXPOSE 8080

# Start the application
CMD ["/usr/local/bin/python", "-m", "uvicorn", "pingpongx.main:app", "--host", "0.0.0.0", "--port", "8080"]
