#!/bin/sh

echo "Waiting for postgres..."

while ! nc -z db 5432; do
  echo "Waiting again"
  sleep 1
done

echo "PostgreSQL started"

python manage.py flush --no-input
python manage.py migrate

exec "$@"