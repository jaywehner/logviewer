# Log Error Summarizer

Local Flask web app that shows a left-hand file tree, lets you view a selected log, and provides an aggregated error summary.

It now uses **simple session-based login** and stores files **per user**.

## Requirements

- Python 3.10+ recommended
- Docker (optional, for containerized deployment)

## Install

# Clone the repository
```bash
git clone https://github.com/jaywehner/logviewer.git
cd logviewer/log_webapp
```

### Local development
```bash
pip install -r requirements.txt
```

### Docker deployment

#### Using docker-compose (recommended)

```bash
# Build and run with docker-compose
docker-compose up --build

# Run in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

#### Using manual Docker commands

```bash
# Build the image
docker build -t log-webapp .

# Run the container
docker run -d \
  --name log-webapp \
  -p 5177:5177 \
  -v $(pwd)/User_Storage:/app/User_Storage \
  -e LOG_WEBAPP_SECRET=your-secret-key \
  log-webapp

# View logs
docker logs -f log-webapp

# Stop and remove the container
docker stop log-webapp
docker rm log-webapp
```

#### Docker Build Troubleshooting

If you encounter timeout errors during the build:

```bash
# Increase build timeout
docker build --timeout 600 -t log-webapp .

# Or use buildkit for better error handling
DOCKER_BUILDKIT=1 docker build -t log-webapp .
```

The Dockerfile includes retry logic and increased timeouts, but network issues may still occur. Try rebuilding if it fails.

#### Docker Runtime Troubleshooting

The application now uses SQLite (users.db) instead of JSON for user management. The database is automatically created and initialized on first run.

If you encounter database-related errors:

```bash
# Stop the container
docker-compose down

# Remove the database file (will be recreated with default admin user)
rm -f users.db

# Restart
docker-compose up -d
```

Default credentials: admin/admin

Note: The SQLite database file is persisted via volume mount at `./users.db:/app/users.db`.

## Run

### Local development

From this folder:

```bash
python app.py
```

Then open:

- http://127.0.0.1:5177

You will be redirected to `/login`.

### Docker with docker-compose

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

The app will be available at http://localhost:5177.

### Docker manual run

```bash
docker run -d \
  --name log-webapp \
  -p 5177:5177 \
  -v $(pwd)/User_Storage:/app/User_Storage \
  -v $(pwd)/users.json:/app/users.json \
  -e LOG_WEBAPP_SECRET=your-secret-key \
  log-webapp
```

## Docker Configuration

- **Port**: 5177 (exposed)
- **Volumes**:
  - `./User_Storage` → `/app/User_Storage` (persists user log files)
  - `./users.json` → `/app/users.json` (persists user accounts)
- **Environment variables**:
  - `LOG_WEBAPP_SECRET`: Secret key for session encryption (change in production)
- **Health check**: `/api/me` endpoint every 30 seconds

## Production Notes

- Set a strong `LOG_WEBAPP_SECRET` environment variable
- Ensure `User_Storage` and `users.json` are backed up regularly
- Consider using a reverse proxy (nginx) for HTTPS in production
- The Dockerfile runs the app with Gunicorn WSGI server (2 workers) as a non-root user for security

## Login

On first run, `users.json` is created with a default user:

- Username: `admin`
- Password: `admin`

## Per-user file storage

Each user is sandboxed to their own folder:

`/User_Storage/<username>/`

The UI supports:

- Upload (multiple files)
- Download (opens in a new tab)
- Delete
- Change password

### Zip upload behavior

If you upload a `.zip` file, the server will:

- Extract it into your user folder
- Recursively look for additional `.zip` files inside extracted content and extract those too
- Delete each `.zip` after it is successfully extracted

## Adding users

Edit `log_webapp/users.json` and add an entry.

`password_hash` must be a Werkzeug password hash. You can generate one with:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('YourPassword'))"
```

## Notes

- The UI is Bootstrap 5 with dark mode (`data-bs-theme="dark"`).
- Log parsing expects lines like:

  `YYYY-MM-DD HH:MM:SS LEVEL message`

- Level toggle supports: `INFO`, `WARNING` (also matches `WARN`), `DEBUG`, `ERROR`, `SEVERE`.
