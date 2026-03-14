#!/bin/bash

# Start script for the Nutrico application
# This script builds and starts the application using Docker Compose.
# Usage:
#   1. Ensure Docker and Docker Compose are installed on your machine.
#   2. Copy .env.example to .env and update the environment variables as needed.
#   3. Run this script: ./start.sh

# Dev 
# docker compose --env-file ../.env --profile dev up -d --build

# Prod
# docker compose --env-file ../.env up --build -d --scale

# Monitoring 
docker compose --env-file ../.env --profile monitoring --profile dev up -d --build