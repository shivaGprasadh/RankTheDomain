# Domain Security Scanner

A comprehensive security scanning and monitoring tool for web domains. This application performs in-depth security analysis of domains, including subdomain discovery, SSL/TLS checks, DNS records, security headers, and more.

## Features

- Multi-domain and subdomain security scanning
- Flexible scanning options (background or synchronous)
- Interactive dashboard with detailed security reporting
- Security ranking system (A+ to E)
- Scheduled automatic scans (every 6 hours)
- CSV and JSON export options
- Fallback processing for resilient operation
- Cross-platform support (macOS, Linux, Windows)

## Installation

### Prerequisites

- Python 3.9+
- pip (Python package manager)
- PostgreSQL (optional, SQLite supported as alternative)
- Redis (optional, for background processing)

### Quick Setup

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/domain-security-scanner.git
   cd domain-security-scanner
   ```

2. Create a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install required packages
   ```bash
   pip install -r project_requirements.txt
   # Ensure python-dotenv is installed
   pip install python-dotenv
   ```

4. Create a `.env` file (optional)
   ```bash
   # Create a .env file with your configuration
   touch .env
   ```

5. Add the following to your `.env` file:
   ```
   # PostgreSQL Database Connection (Optional)
   # Comment out to use SQLite instead
   # DATABASE_URL=postgresql://domainscanner:domainscanner@localhost:5432/domain_security_scanner

   # Application Secret Key
   SESSION_SECRET=your_secure_secret_key_here

   # Optional: Debug Mode
   DEBUG=True

   # Optional: VirusTotal API Key (if used for threat intelligence)
   # VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ```

## Database Setup Options

### Option 1: Using SQLite (Simplest)

No additional setup required. Just make sure the `DATABASE_URL` line in your `.env` file is commented out or removed. The application will automatically create a `domain_scanner.db` file in the project directory.

### Option 2: Using PostgreSQL

1. Make sure PostgreSQL is installed and running
   ```bash
   # On macOS
   brew services start postgresql
   
   # On Ubuntu/Debian
   sudo service postgresql start
   ```

2. Create a database and user
   ```bash
   # Create user with password
   createuser -P domainscanner
   # When prompted, enter 'domainscanner' as the password
   
   # Create database
   createdb domain_security_scanner
   
   # Grant privileges to the user
   psql -c "GRANT ALL PRIVILEGES ON DATABASE domain_security_scanner TO domainscanner;"
   ```

3. Uncomment the `DATABASE_URL` line in your `.env` file:
   ```
   DATABASE_URL=postgresql://domainscanner:domainscanner@localhost:5432/domain_security_scanner
   ```

## Running the Application

### Basic Mode (without background processing)

```bash
python main.py
# The application will be available at http://localhost:5000
```

### Full Mode (with background processing using Redis)

1. Start Redis (in a separate terminal)
   ```bash
   redis-server --bind 0.0.0.0 --port 6379
   ```

2. Start Celery worker (in another terminal)
   ```bash
   chmod +x run_celery_worker.sh
   ./run_celery_worker.sh  # or: celery -A tasks worker --loglevel=info
   ```

3. Start the Flask application
   ```bash
   python main.py
   ```

### All-in-One Startup Script

A convenience script is provided to start all services:
```bash
chmod +x start_services.sh
./start_services.sh
```

## Common Issues and Solutions

### PostgreSQL Connection Error

If you see an error like:
```
FATAL: role "domainscanner" does not exist
```

You have two options:
1. **Switch to SQLite**: Comment out the `DATABASE_URL` line in your `.env` file
2. **Create the PostgreSQL user**: Follow the steps in the "Using PostgreSQL" section above

### Redis Connection Errors

If you see Redis connection errors, but don't need background processing, you can ignore them. The application includes a fallback mechanism that will process domains synchronously.

If you want to use Redis:
1. Install Redis: 
   ```bash
   # macOS
   brew install redis
   # Ubuntu/Debian
   sudo apt install redis-server
   ```
2. Start Redis with proper binding:
   ```bash
   redis-server --bind 0.0.0.0 --port 6379
   ```

## License

Copyright © 2025

## Acknowledgments

- All the open-source libraries and tools used in this project