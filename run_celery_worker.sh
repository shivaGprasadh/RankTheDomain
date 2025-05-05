#!/bin/bash

# Start Redis server (if not already running)
echo "Starting Redis server..."
redis-server --bind 0.0.0.0 --daemonize yes

# Start Celery worker
echo "Starting Celery worker..."
celery -A celery_config worker --loglevel=info