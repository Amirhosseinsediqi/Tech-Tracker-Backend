#!/bin/bash

echo "Starting stress test..."

# Build and start the containers
docker compose down -v
docker compose up -d

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 30

# Run the stress test
echo "Running stress test..."
docker compose exec dev node db-stress-test.js

# Monitor MongoDB logs
echo "Monitoring MongoDB logs..."
docker compose logs -f mongodb &

# Monitor container stats
echo "Monitoring container stats..."
docker stats --no-stream mongodb dev

# Cleanup
echo "Test complete. Press Ctrl+C to stop monitoring."
