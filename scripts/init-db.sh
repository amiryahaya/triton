#!/bin/bash
set -e

# Create additional databases needed by Triton services.
# This script runs automatically on first PostgreSQL container startup
# via docker-entrypoint-initdb.d.

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    SELECT 'CREATE DATABASE triton_license'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'triton_license')\gexec

    SELECT 'CREATE DATABASE triton_manage'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'triton_manage')\gexec

    SELECT 'CREATE DATABASE triton_test'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'triton_test')\gexec
EOSQL
