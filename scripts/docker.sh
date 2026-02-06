#!/bin/bash
# VeilArmor - Docker Deployment Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
IMAGE_NAME="veilarmor"
IMAGE_TAG="2.0.0"
CONTAINER_NAME="veilarmor"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build)
            BUILD=true
            shift
            ;;
        --start)
            START=true
            shift
            ;;
        --stop)
            STOP=true
            shift
            ;;
        --restart)
            RESTART=true
            shift
            ;;
        --logs)
            LOGS=true
            shift
            ;;
        --shell)
            SHELL=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        --with-monitoring)
            WITH_MONITORING=true
            shift
            ;;
        --tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --help)
            echo "VeilArmor Docker Deployment Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --build            Build Docker image"
            echo "  --start            Start containers"
            echo "  --stop             Stop containers"
            echo "  --restart          Restart containers"
            echo "  --logs             Show logs"
            echo "  --shell            Open shell in container"
            echo "  --clean            Remove containers and images"
            echo "  --with-monitoring  Include Prometheus/Grafana"
            echo "  --tag TAG          Specify image tag"
            echo "  --help             Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

cd "$PROJECT_DIR"

# Build image
if [ "$BUILD" = true ]; then
    echo -e "${BLUE}Building Docker image...${NC}"
    docker build -t "$IMAGE_NAME:$IMAGE_TAG" -t "$IMAGE_NAME:latest" .
    echo -e "${GREEN}Image built: $IMAGE_NAME:$IMAGE_TAG${NC}"
fi

# Start containers
if [ "$START" = true ]; then
    echo -e "${BLUE}Starting containers...${NC}"
    
    if [ "$WITH_MONITORING" = true ]; then
        docker compose --profile monitoring up -d
    else
        docker compose up -d
    fi
    
    echo -e "${GREEN}Containers started${NC}"
    echo ""
    echo "VeilArmor is running at: http://localhost:8000"
    echo "API Documentation: http://localhost:8000/docs"
    
    if [ "$WITH_MONITORING" = true ]; then
        echo "Prometheus: http://localhost:9090"
        echo "Grafana: http://localhost:3000"
    fi
fi

# Stop containers
if [ "$STOP" = true ]; then
    echo -e "${BLUE}Stopping containers...${NC}"
    docker compose --profile monitoring down
    echo -e "${GREEN}Containers stopped${NC}"
fi

# Restart containers
if [ "$RESTART" = true ]; then
    echo -e "${BLUE}Restarting containers...${NC}"
    docker compose restart
    echo -e "${GREEN}Containers restarted${NC}"
fi

# Show logs
if [ "$LOGS" = true ]; then
    docker compose logs -f veilarmor
fi

# Open shell
if [ "$SHELL" = true ]; then
    docker compose exec veilarmor /bin/bash
fi

# Clean up
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning up Docker resources...${NC}"
    docker compose --profile monitoring down -v --rmi local
    echo -e "${GREEN}Cleanup complete${NC}"
fi

# Default action: show status
if [ -z "$BUILD" ] && [ -z "$START" ] && [ -z "$STOP" ] && [ -z "$RESTART" ] && [ -z "$LOGS" ] && [ -z "$SHELL" ] && [ -z "$CLEAN" ]; then
    echo -e "${BLUE}Container Status:${NC}"
    docker compose ps
fi
