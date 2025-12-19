# API Translation Platform Deployment Guide

This document provides comprehensive deployment instructions and procedures for the API Translation Platform.

## Overview

The API Translation Platform supports multiple deployment scenarios:
- **Local Development**: Docker Compose for local testing
- **Staging Environment**: Kubernetes deployment with basic monitoring
- **Production Environment**: Full Kubernetes deployment with HA, monitoring, and backup

## Prerequisites

### Required Tools
- Docker and Docker Compose
- Kubernetes cluster (for production/staging)
- kubectl configured for your cluster
- Go 1.24+ (for building from source)
- PostgreSQL 15+
- Redis 7+

### Environment Variables

The following environment variables must be configured for production:

```bash
# Database Configuration
DATABASE_HOST=your-postgres-host
DATABASE_PORT=5432
DATABASE_USER=your-db-user
DATABASE_PASSWORD=your-db-password
DATABASE_NAME=api_translation_platform

# Redis Configuration
REDIS_HOST=your-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0

# Security Configuration
ALLOWED_ORIGINS=https://yourdomain.com
JWT_SECRET=your-jwt-secret

# Monitoring Configuration
JAEGER_ENDPOINT=http://jaeger:14268/api/traces
ALERT_MANAGER_URL=http://alertmanager:9093

# Backup Configuration
BACKUP_S3_BUCKET=your-backup-bucket
BACKUP_S3_REGION=us-west-2
```

## Local Development Deployment

### Using Docker Compose

1. **Start the full stack:**
   ```bash
   docker-compose up -d
   ```

2. **Verify deployment:**
   ```bash
   curl http://localhost/health
   ```

3. **View logs:**
   ```bash
   docker-compose logs -f api-platform-1
   ```

4. **Stop the stack:**
   ```bash
   docker-compose down
   ```

### Individual Services

The docker-compose setup includes:
- 3 API Translation Platform instances (ports 8080-8082)
- PostgreSQL database (port 5432)
- Redis cache (port 6379)
- Nginx load balancer (port 80)

## Kubernetes Deployment

### Staging Environment

1. **Create namespace:**
   ```bash
   kubectl apply -f deployments/kubernetes/namespace.yaml
   ```

2. **Deploy configuration:**
   ```bash
   kubectl apply -f deployments/kubernetes/configmap.yaml
   ```

3. **Deploy RBAC:**
   ```bash
   kubectl apply -f deployments/kubernetes/rbac.yaml
   ```

4. **Deploy application:**
   ```bash
   kubectl apply -f deployments/kubernetes/deployment.yaml
   kubectl apply -f deployments/kubernetes/service.yaml
   ```

5. **Verify deployment:**
   ```bash
   kubectl get pods -n api-translation-platform
   kubectl logs -f deployment/api-translation-platform -n api-translation-platform
   ```

### Production Environment

1. **Deploy all components:**
   ```bash
   kubectl apply -f deployments/kubernetes/namespace.yaml
   kubectl apply -f deployments/kubernetes/configmap.yaml
   kubectl apply -f deployments/kubernetes/rbac.yaml
   kubectl apply -f deployments/kubernetes/deployment.yaml
   kubectl apply -f deployments/kubernetes/service.yaml
   kubectl apply -f deployments/kubernetes/hpa.yaml
   kubectl apply -f deployments/kubernetes/ingress.yaml
   ```

2. **Verify horizontal pod autoscaler:**
   ```bash
   kubectl get hpa -n api-translation-platform
   ```

3. **Check ingress:**
   ```bash
   kubectl get ingress -n api-translation-platform
   ```

## CI/CD Pipeline

The project includes a comprehensive GitHub Actions workflow (`.github/workflows/ci-cd.yml`) that:

### Continuous Integration
- Runs unit tests and property-based tests
- Performs security scanning with Gosec and Trivy
- Builds multi-platform Docker images
- Validates deployment configurations

### Continuous Deployment
- **Staging**: Automatic deployment on `develop` branch
- **Production**: Deployment on release creation
- Includes smoke tests and health checks
- Automatic rollback on failure

### Pipeline Stages

1. **Test Stage**
   - Unit tests with PostgreSQL and Redis services
   - Property-based tests
   - Coverage reporting

2. **Security Scan Stage**
   - Static code analysis with Gosec
   - Vulnerability scanning with Trivy

3. **Build Stage**
   - Multi-platform Docker builds (amd64, arm64)
   - Container registry push

4. **Deployment Tests Stage**
   - Validates deployment configurations
   - Tests Docker Compose setup

5. **Deploy Staging Stage**
   - Deploys to staging environment
   - Runs smoke tests

6. **Deploy Production Stage**
   - Creates database backup before deployment
   - Deploys to production
   - Runs comprehensive health checks
   - Sends deployment notifications

## Monitoring and Alerting

### Prometheus Configuration

The platform exposes metrics on `/metrics` endpoint. Configure Prometheus to scrape:

```yaml
scrape_configs:
  - job_name: 'api-translation-platform'
    static_configs:
      - targets: ['api-translation-platform-service:80']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Alert Rules

Key alerts are configured in `deployments/monitoring/alert_rules.yml`:

- **HighErrorRate**: Error rate > 5% for 5 minutes
- **HighLatency**: 95th percentile latency > 1s for 5 minutes
- **ServiceDown**: Service unavailable for 1 minute
- **HighMemoryUsage**: Memory usage > 80% for 10 minutes
- **HighCPUUsage**: CPU usage > 80% for 10 minutes

### Health Check Endpoints

- `/health`: Basic health check
- `/health/live`: Liveness probe (Kubernetes)
- `/health/ready`: Readiness probe (Kubernetes)
- `/metrics`: Prometheus metrics

## Backup and Recovery

### Automated Backups

Production deployments include automated daily backups:

```bash
# Manual backup
./scripts/backup.sh

# Backup with custom retention
RETENTION_DAYS=60 ./scripts/backup.sh
```

### Recovery Procedures

1. **Restore from latest backup:**
   ```bash
   ./scripts/recovery.sh latest
   ```

2. **Restore from specific backup:**
   ```bash
   ./scripts/recovery.sh /backups/backup_20231201_120000.tar.gz
   ```

3. **Restore from S3:**
   ```bash
   ./scripts/recovery.sh s3://my-bucket/backups/backup_20231201_120000.tar.gz
   ```

### Backup Components

- PostgreSQL database dump
- Kubernetes ConfigMaps and Secrets
- Deployment configurations
- Application logs (optional)

## Security Configuration

### Container Security

- Runs as non-root user (UID 1000)
- Read-only root filesystem
- Dropped capabilities
- Security context enforcement

### Network Security

- TLS termination at ingress
- Internal service communication
- Network policies (optional)
- CORS configuration

### Authentication & Authorization

- JWT-based authentication
- Role-based access control (RBAC)
- API key authentication
- OAuth integration support

## Scaling and Performance

### Horizontal Pod Autoscaler

The HPA configuration automatically scales based on:
- CPU utilization (target: 70%)
- Memory utilization (target: 80%)
- Min replicas: 3
- Max replicas: 10

### Resource Limits

Per pod resource configuration:
- **Requests**: 250m CPU, 256Mi memory
- **Limits**: 500m CPU, 512Mi memory

### Load Balancing

- Nginx load balancer for Docker Compose
- Kubernetes Service for cluster deployments
- Health check-based routing
- Session affinity support

## Troubleshooting

### Common Issues

1. **Pod CrashLoopBackOff**
   ```bash
   kubectl describe pod <pod-name> -n api-translation-platform
   kubectl logs <pod-name> -n api-translation-platform --previous
   ```

2. **Database Connection Issues**
   ```bash
   kubectl exec -it <pod-name> -n api-translation-platform -- env | grep DATABASE
   ```

3. **High Memory Usage**
   ```bash
   kubectl top pods -n api-translation-platform
   ```

### Log Analysis

- Application logs: JSON format with structured fields
- Access logs: Nginx format with request details
- Error logs: Stack traces and context information

### Performance Debugging

1. **Check metrics:**
   ```bash
   curl http://localhost/metrics
   ```

2. **Database performance:**
   ```bash
   kubectl exec -it postgres-pod -- psql -U postgres -c "SELECT * FROM pg_stat_activity;"
   ```

3. **Redis performance:**
   ```bash
   kubectl exec -it redis-pod -- redis-cli info stats
   ```

## Disaster Recovery

### Multi-Region Setup

For disaster recovery, deploy to multiple regions:

1. **Primary Region**: Full deployment with read/write database
2. **Secondary Region**: Read-only replicas with failover capability
3. **Database Replication**: PostgreSQL streaming replication
4. **Data Synchronization**: Redis cluster or replication

### Failover Procedures

1. **Automatic Failover**: Health checks trigger DNS updates
2. **Manual Failover**: Update ingress to point to secondary region
3. **Database Failover**: Promote read replica to primary

### Recovery Time Objectives

- **RTO (Recovery Time Objective)**: < 15 minutes
- **RPO (Recovery Point Objective)**: < 5 minutes
- **Backup Retention**: 30 days local, 90 days S3

## Maintenance

### Regular Maintenance Tasks

1. **Weekly**:
   - Review application logs
   - Check resource utilization
   - Verify backup integrity

2. **Monthly**:
   - Update dependencies
   - Review security patches
   - Performance optimization

3. **Quarterly**:
   - Disaster recovery testing
   - Security audit
   - Capacity planning

### Update Procedures

1. **Rolling Updates**: Zero-downtime deployments
2. **Blue-Green Deployments**: For major updates
3. **Canary Deployments**: For gradual rollouts

## Support and Documentation

### Additional Resources

- [API Documentation](../docs/api.md)
- [Configuration Reference](../docs/configuration.md)
- [Development Guide](../docs/development.md)
- [Security Guide](../docs/security.md)

### Getting Help

- GitHub Issues: Bug reports and feature requests
- Documentation: Comprehensive guides and references
- Monitoring: Real-time metrics and alerting