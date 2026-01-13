#!/bin/bash
# Docker rebuild script for Security One IDS
# This script is called from within the container to trigger a rebuild

set -e

echo "$(date) - Starting Docker rebuild..."

# Get the directory where docker-compose.yml is located
COMPOSE_DIR="/var/www"

# Check if we have access to docker socket (should be mounted)
if [ -S /var/run/docker.sock ]; then
    echo "$(date) - Docker socket available, rebuilding..."
    cd $COMPOSE_DIR
    docker-compose build app
    docker-compose up -d app
    echo "$(date) - Docker rebuild completed successfully"
else
    echo "$(date) - Docker socket not available, cannot rebuild from inside container"
    echo "$(date) - Please run 'docker-compose build app && docker-compose up -d' manually"
    exit 1
fi
