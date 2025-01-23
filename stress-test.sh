#!/bin/bash

echo "Starting stress test..."

# Cleanup existing containers and volumes
echo "Cleaning up existing containers and volumes..."
docker compose down -v

# Start containers
echo "Starting containers..."
docker compose up -d

# Wait for MongoDB to be healthy
echo "Waiting for mongodb to be healthy..."
until docker compose exec mongodb mongosh --eval "db.runCommand({ ping: 1 })" > /dev/null 2>&1; do
    sleep 1
done
echo "mongodb is healthy!"

# Wait for Redis to be healthy
echo "Waiting for redis to be healthy..."
until docker compose exec redis redis-cli ping > /dev/null 2>&1; do
    sleep 1
done
echo "redis is healthy!"

# Wait for dev service to start
echo "Waiting for dev service to start..."
echo "Checking dev service logs..."
docker compose logs dev

# Wait for the health endpoint
max_attempts=30
attempt=1
while [ $attempt -le $max_attempts ]; do
    echo "Attempt $attempt/$max_attempts: Checking dev service health..."
    if curl -s http://localhost:5502/health > /dev/null; then
        echo "dev service is healthy!"
        break
    fi
    
    # Show recent logs if the service is not responding
    if [ $((attempt % 5)) -eq 0 ]; then
        echo "Recent dev service logs:"
        docker compose logs --tail=20 dev
    fi
    
    attempt=$((attempt + 1))
    sleep 2
done

if [ $attempt -gt $max_attempts ]; then
    echo "Error: Dev service failed to become healthy after $max_attempts attempts"
    echo "Full dev service logs:"
    docker compose logs dev
    exit 1
fi

echo "All services are healthy. Starting stress test..."

# Run the stress test
echo "Running stress test..."
if ! docker compose exec dev node db-stress-test.js; then
    echo "Error running stress test"
    docker compose logs dev
    exit 1
fi

echo "Stress test completed successfully!"
