#!/bin/bash
set -e

echo "Esperando a MySQL..."
sleep 10

echo "Ejecutando migraciones..."
python manage.py migrate --no-input

echo "Iniciando Gunicorn..."
exec gunicorn \
  --bind 0.0.0.0:8000 \
  --workers 3 \
  --timeout 120 \
  GTEA_Project_API.wsgi:application
