#!/bin/bash
set -e

# Read environment variables (fallback to defaults if not set)
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
DB_PASSWORD=${DB_PASSWORD:-postgres}
DB_NAME=${DB_NAME:-horizon}

# Wait for PostgreSQL to be ready (max 30 attempts)
echo "⏳ Waiting for PostgreSQL at $DB_HOST:$DB_PORT..."
for i in {1..30}; do
  if PGPASSWORD=$DB_PASSWORD psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c '\q' >/dev/null 2>&1; then
    echo "✅ PostgreSQL is ready!"
    break
  fi
  echo "⏳ Attempt $i/30 - PostgreSQL not ready, sleeping 2s..."
  sleep 2
done

# Start the main Horizon Angel binary
echo "🚀 Starting Horizon Angel Panel..."
exec ./horizon
