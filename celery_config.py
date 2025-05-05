import os
from celery import Celery

# In Replit environment, we need to listen on 0.0.0.0 instead of localhost
REDIS_HOST = '0.0.0.0'
REDIS_PORT = 6379
REDIS_URL = f'redis://{REDIS_HOST}:{REDIS_PORT}/0'

# Initialize Celery
celery_app = Celery('domain_scanner',
                broker=os.environ.get('REDIS_URL', REDIS_URL),
                backend=os.environ.get('REDIS_URL', REDIS_URL),
                include=['tasks'])

# Configure Celery settings
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    worker_concurrency=4,  # Adjust this based on your server's CPU cores
    task_time_limit=600,   # 10 minutes time limit per task
    worker_max_memory_per_child=200000,  # 200MB memory limit
    broker_connection_retry_on_startup=True,
)

# Optional: Configure scheduled tasks
celery_app.conf.beat_schedule = {
    'scheduled-scan-every-6h': {
        'task': 'tasks.scheduled_full_scan',
        'schedule': 21600.0,  # 6 hours in seconds
    },
}

if __name__ == '__main__':
    celery_app.start()