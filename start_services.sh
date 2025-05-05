#!/bin/bash

# Make script executable
chmod +x start_services.sh

# Start Redis server (if not already running)
echo "Starting Redis server..."
redis-server --bind 0.0.0.0 --daemonize yes

# Start Celery worker in the background
echo "Starting Celery worker..."
celery -A celery_config worker --loglevel=info > celery_worker.log 2>&1 &

# Start the web application
echo "Starting web application..."
gunicorn --bind 0.0.0.0:5000 --workers=1 main:app