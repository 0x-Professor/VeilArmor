# VeilArmor v2.0 - Deployment Guide

## Overview

This guide covers deploying VeilArmor in various environments from development to production.

## Quick Start

### Local Development

```bash
# Clone repository
git clone https://github.com/your-org/veilarmor.git
cd veilarmor

# Run setup script
./scripts/setup.sh

# Start development server
./scripts/cli.py serve --dev
```

### Docker

```bash
# Build image
docker build -t veilarmor:2.0 .

# Run container
docker run -p 8000:8000 \
  -e OPENAI_API_KEY=sk-xxx \
  veilarmor:2.0
```

### Docker Compose (Full Stack)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f veilarmor

# Stop services
docker-compose down
```

## Docker Deployment

### Dockerfile

VeilArmor uses a multi-stage build for minimal image size:

```dockerfile
# Build stage
FROM python:3.11-slim as builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
EXPOSE 8000
CMD ["python", "main.py"]
```

### Docker Compose Stack

The full stack includes:

- **VeilArmor**: Main application (port 8000)
- **Redis**: Caching and session storage (port 6379)
- **Prometheus**: Metrics collection (port 9090)
- **Grafana**: Dashboard visualization (port 3000)

```yaml
# docker-compose.yml
version: '3.8'
services:
  veilarmor:
    build: .
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./deploy/prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
```

### Environment Variables

```bash
# Required
OPENAI_API_KEY=sk-xxx           # At least one LLM provider

# Optional
ANTHROPIC_API_KEY=sk-ant-xxx
REDIS_URL=redis://localhost:6379
VEILARMOR_LOG_LEVEL=INFO
VEILARMOR_API_PORT=8000
```

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.20+)
- kubectl configured
- Helm 3.x (optional)

### Namespace

```bash
# Create namespace
kubectl create namespace veilarmor
```

### Deploy with kubectl

```bash
# Apply all manifests
kubectl apply -f deploy/kubernetes/

# Check status
kubectl -n veilarmor get all
```

### Manifests Overview

| File | Description |
|------|-------------|
| `configmap.yaml` | ConfigMap with settings |
| `deployment.yaml` | Main deployment with HPA |
| `service.yaml` | Service and Ingress |
| `redis.yaml` | Redis deployment |
| `rbac.yaml` | RBAC configuration |

### Scaling

```yaml
# HorizontalPodAutoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: veilarmor-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: veilarmor
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Resource Limits

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

### Health Probes

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Secrets

```bash
# Create secrets
kubectl -n veilarmor create secret generic veilarmor-secrets \
  --from-literal=OPENAI_API_KEY=sk-xxx \
  --from-literal=API_KEY=your-api-key
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: veilarmor-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - veilarmor.example.com
      secretName: veilarmor-tls
  rules:
    - host: veilarmor.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: veilarmor
                port:
                  number: 8000
```

## AWS Deployment

### ECS with Fargate

```bash
# Create cluster
aws ecs create-cluster --cluster-name veilarmor

# Create task definition
aws ecs register-task-definition --cli-input-json file://aws/task-definition.json

# Create service
aws ecs create-service \
  --cluster veilarmor \
  --service-name veilarmor-service \
  --task-definition veilarmor:1 \
  --desired-count 2 \
  --launch-type FARGATE
```

### Lambda (Serverless)

For serverless deployment, use the lightweight handler:

```python
# handler.py
from mangum import Mangum
from src.api.server import create_app

app = create_app()
handler = Mangum(app)
```

## Production Checklist

### Security

- [ ] Enable authentication
- [ ] Configure TLS/HTTPS
- [ ] Set strong API keys
- [ ] Enable rate limiting
- [ ] Configure network policies
- [ ] Review CORS settings
- [ ] Enable audit logging

### Performance

- [ ] Enable Redis caching
- [ ] Configure appropriate resources
- [ ] Set up HPA for auto-scaling
- [ ] Enable connection pooling
- [ ] Configure worker count

### Reliability

- [ ] Set up health checks
- [ ] Configure pod disruption budget
- [ ] Enable circuit breaker
- [ ] Set up retries
- [ ] Configure timeouts

### Monitoring

- [ ] Enable Prometheus metrics
- [ ] Set up Grafana dashboards
- [ ] Configure alerting
- [ ] Enable structured logging
- [ ] Set up log aggregation

### Backup

- [ ] Configure Redis persistence
- [ ] Set up conversation backup
- [ ] Document recovery procedures

## Monitoring Setup

### Prometheus Configuration

```yaml
# deploy/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'veilarmor'
    static_configs:
      - targets: ['veilarmor:8000']
    metrics_path: '/metrics'
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `veilarmor_requests_total` | Total requests by action |
| `veilarmor_request_duration_seconds` | Request latency histogram |
| `veilarmor_classification_duration_seconds` | Classification latency |
| `veilarmor_cache_hits_total` | Cache hit count |
| `veilarmor_threats_detected_total` | Threats by type |
| `veilarmor_llm_latency_seconds` | LLM provider latency |

### Alerting Rules

```yaml
groups:
  - name: veilarmor
    rules:
      - alert: HighErrorRate
        expr: rate(veilarmor_requests_total{action="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected

      - alert: HighBlockRate
        expr: rate(veilarmor_requests_total{action="block"}[5m]) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Unusually high block rate
```

## Troubleshooting

### Common Issues

**1. Container won't start**
```bash
# Check logs
docker logs veilarmor

# Common causes:
# - Missing API keys
# - Redis connection failed
# - Port already in use
```

**2. High latency**
```bash
# Check metrics
curl localhost:8000/metrics | grep duration

# Solutions:
# - Enable caching
# - Reduce classifier count
# - Scale horizontally
```

**3. Memory issues**
```bash
# Monitor memory
docker stats veilarmor

# Solutions:
# - Increase memory limit
# - Reduce cache size
# - Enable Redis for caching
```

### Debug Mode

```bash
# Enable debug logging
VEILARMOR_DEBUG=true \
VEILARMOR_LOG_LEVEL=DEBUG \
python main.py
```

## Upgrade Guide

### Rolling Update

```bash
# Update image
docker build -t veilarmor:2.1 .

# Rolling update in Kubernetes
kubectl -n veilarmor set image deployment/veilarmor \
  veilarmor=veilarmor:2.1

# Watch rollout
kubectl -n veilarmor rollout status deployment/veilarmor
```

### Rollback

```bash
# Rollback to previous version
kubectl -n veilarmor rollout undo deployment/veilarmor
```

## Support

- Documentation: `/docs`
- Issues: GitHub Issues
- Community: Discord/Slack
