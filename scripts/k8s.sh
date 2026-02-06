#!/bin/bash
# VeilArmor - Kubernetes Deployment Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
K8S_DIR="$PROJECT_DIR/deploy/kubernetes"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
NAMESPACE="veilarmor"
IMAGE_TAG="2.0.0"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --deploy)
            DEPLOY=true
            shift
            ;;
        --delete)
            DELETE=true
            shift
            ;;
        --status)
            STATUS=true
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
        --port-forward)
            PORT_FORWARD=true
            shift
            ;;
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --tag)
            IMAGE_TAG="$2"
            shift 2
            ;;
        --help)
            echo "VeilArmor Kubernetes Deployment Script"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --deploy         Deploy to Kubernetes"
            echo "  --delete         Delete deployment"
            echo "  --status         Show deployment status"
            echo "  --logs           Show pod logs"
            echo "  --shell          Open shell in pod"
            echo "  --port-forward   Forward port to local"
            echo "  --namespace NS   Specify namespace"
            echo "  --tag TAG        Specify image tag"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check kubectl
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}kubectl is not installed${NC}"
    exit 1
fi

# Deploy
if [ "$DEPLOY" = true ]; then
    echo -e "${BLUE}Deploying VeilArmor to Kubernetes...${NC}"
    
    # Apply manifests in order
    kubectl apply -f "$K8S_DIR/configmap.yaml"
    kubectl apply -f "$K8S_DIR/rbac.yaml"
    kubectl apply -f "$K8S_DIR/redis.yaml"
    kubectl apply -f "$K8S_DIR/deployment.yaml"
    kubectl apply -f "$K8S_DIR/service.yaml"
    
    echo -e "${GREEN}Deployment complete${NC}"
    echo ""
    echo "Wait for pods to be ready:"
    echo "  kubectl -n $NAMESPACE get pods -w"
fi

# Delete
if [ "$DELETE" = true ]; then
    echo -e "${YELLOW}Deleting VeilArmor deployment...${NC}"
    
    kubectl delete -f "$K8S_DIR/service.yaml" --ignore-not-found
    kubectl delete -f "$K8S_DIR/deployment.yaml" --ignore-not-found
    kubectl delete -f "$K8S_DIR/redis.yaml" --ignore-not-found
    kubectl delete -f "$K8S_DIR/rbac.yaml" --ignore-not-found
    kubectl delete -f "$K8S_DIR/configmap.yaml" --ignore-not-found
    
    echo -e "${GREEN}Deployment deleted${NC}"
fi

# Status
if [ "$STATUS" = true ]; then
    echo -e "${BLUE}VeilArmor Deployment Status:${NC}"
    echo ""
    echo "Pods:"
    kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=veilarmor
    echo ""
    echo "Services:"
    kubectl -n "$NAMESPACE" get svc -l app.kubernetes.io/name=veilarmor
    echo ""
    echo "Deployments:"
    kubectl -n "$NAMESPACE" get deployments -l app.kubernetes.io/name=veilarmor
fi

# Logs
if [ "$LOGS" = true ]; then
    POD=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=veilarmor,app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')
    kubectl -n "$NAMESPACE" logs -f "$POD"
fi

# Shell
if [ "$SHELL" = true ]; then
    POD=$(kubectl -n "$NAMESPACE" get pods -l app.kubernetes.io/name=veilarmor,app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')
    kubectl -n "$NAMESPACE" exec -it "$POD" -- /bin/bash
fi

# Port forward
if [ "$PORT_FORWARD" = true ]; then
    echo -e "${BLUE}Forwarding port 8000 to localhost...${NC}"
    echo "Access VeilArmor at: http://localhost:8000"
    kubectl -n "$NAMESPACE" port-forward svc/veilarmor 8000:80
fi

# Default: show status
if [ -z "$DEPLOY" ] && [ -z "$DELETE" ] && [ -z "$STATUS" ] && [ -z "$LOGS" ] && [ -z "$SHELL" ] && [ -z "$PORT_FORWARD" ]; then
    echo -e "${BLUE}VeilArmor Kubernetes Deployment Script${NC}"
    echo "Use --help to see available options"
    echo ""
    echo "Quick start:"
    echo "  $0 --deploy       # Deploy to cluster"
    echo "  $0 --status       # Check status"
    echo "  $0 --port-forward # Access locally"
fi
