# Use official Python image

FROM python:3.12-slim
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt ./
COPY requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -r requirements-prod.txt

# Copy source code
COPY codec ./codec

# Expose the port the server runs on
EXPOSE 6000

# Run the server with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:6000", "codec.codec_server:app"]
