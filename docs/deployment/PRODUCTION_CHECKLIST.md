# Production Deployment Checklist

This checklist ensures all critical components are properly configured before deploying to production.

## Pre-Deployment Checklist

### Infrastructure Requirements
- [ ] Kubernetes cluster is running and accessible
- [ ] PostgreSQL database is deployed and configured
- [ ] Redis cache is deployed and configured
- [ ] Load balancer is configured
- [ ] SSL certificates are installed and valid
- [ ] DNS records are configured
- [ ] Monitoring infrastructure is deployed (Prometheus, Grafana)
- [ ] Log aggregation is configured (ELK stack or similar)

### Security Configuration
- [ ] All secrets are stored in Kubernetes secrets (not ConfigMaps)
- [ ] Database passwords are rotated and secure
- [ ] JWT secrets are generated and secure
- [ ] TLS is enabled for all external communications
- [ ] Network policies are configured (if applicable)
- [ ] RBAC permissions are properly configured
- [ ] Container images are scanned for vulnerabilities
- [ ] Security contexts are properly configured

### Environment Configuration
- [ ] All required environment variables are set
- [ ] Configuration files are validated
- [ ] Database connection strings are correct
- [ ] Redis connection parameters are correct
- [ ] External API endpoints are accessible
- [ ] Resource limits and requests are appropriate
- [ ] Health check endpoints are configured

### Backup and Recovery
- [ ] Backup scripts are tested and working
- [ ] Recovery scripts are tested and working
- [ ] Backup storage (S3) is configured and accessible
- [ ] Backup retention policies are configured
- [ ] Recovery procedures are documented
- [ ] Disaster recovery plan is in place

### Monitoring and Alerting
- [ ] Prometheus is scraping application metrics
- [ ] Alert rules are configured and tested
- [ ] Alert manager is configured
- [ ] Notification channels are configured (Slack, email, etc.)
- [ ] Dashboards are created and accessible
- [ ] Log aggregation is working
- [ ] Health check monitoring is configured

### Performance and Scaling
- [ ] Horizontal Pod Autoscaler is configured
- [ ] Resource limits are appropriate for expected load
- [ ] Load testing has been performed
- [ ] Database performance is optimized
- [ ] Caching strategies are implemented
- [ ] CDN is configured (if applicable)

## Deployment Process

### Step 1: Pre-deployment Validation
- [ ] Run deployment tests: `go test ./deployments/tests/...`
- [ ] Validate Kubernetes manifests: `kubectl apply --dry-run=client -f deployments/kubernetes/`
- [ ] Check resource quotas and limits
- [ ] Verify all dependencies are available

### Step 2: Database Preparation
- [ ] Create database backup before deployment
- [ ] Run database migrations (if any)
- [ ] Verify database connectivity from application pods
- [ ] Check database performance metrics

### Step 3: Application Deployment
- [ ] Deploy namespace: `kubectl apply -f deployments/kubernetes/namespace.yaml`
- [ ] Deploy ConfigMap: `kubectl apply -f deployments/kubernetes/configmap.yaml`
- [ ] Deploy RBAC: `kubectl apply -f deployments/kubernetes/rbac.yaml`
- [ ] Deploy application: `kubectl apply -f deployments/kubernetes/deployment.yaml`
- [ ] Deploy service: `kubectl apply -f deployments/kubernetes/service.yaml`
- [ ] Deploy HPA: `kubectl apply -f deployments/kubernetes/hpa.yaml`
- [ ] Deploy ingress: `kubectl apply -f deployments/kubernetes/ingress.yaml`

### Step 4: Post-deployment Validation
- [ ] Verify all pods are running: `kubectl get pods -n api-translation-platform`
- [ ] Check pod logs for errors: `kubectl logs -f deployment/api-translation-platform -n api-translation-platform`
- [ ] Test health endpoints: `curl https://yourdomain.com/health`
- [ ] Verify metrics are being collected
- [ ] Test API functionality
- [ ] Verify load balancing is working

### Step 5: Monitoring Setup
- [ ] Confirm metrics are being scraped by Prometheus
- [ ] Verify alerts are configured and firing (test with intentional issues)
- [ ] Check dashboard functionality
- [ ] Verify log aggregation is working
- [ ] Test notification channels

## Post-Deployment Checklist

### Immediate (0-1 hour)
- [ ] Monitor application logs for errors
- [ ] Check resource utilization
- [ ] Verify all health checks are passing
- [ ] Test critical API endpoints
- [ ] Monitor error rates and response times

### Short-term (1-24 hours)
- [ ] Monitor application performance metrics
- [ ] Check for memory leaks or resource issues
- [ ] Verify backup jobs are running successfully
- [ ] Monitor database performance
- [ ] Check for any security alerts

### Medium-term (1-7 days)
- [ ] Review application logs for patterns
- [ ] Analyze performance trends
- [ ] Verify autoscaling is working correctly
- [ ] Check backup integrity
- [ ] Review security audit logs

## Rollback Procedures

### Automatic Rollback Triggers
- [ ] Health check failures for > 5 minutes
- [ ] Error rate > 10% for > 2 minutes
- [ ] Response time > 5s for > 2 minutes
- [ ] Memory usage > 90% for > 5 minutes

### Manual Rollback Steps
1. [ ] Identify the issue and confirm rollback is necessary
2. [ ] Create incident ticket/communication
3. [ ] Execute rollback: `kubectl rollout undo deployment/api-translation-platform -n api-translation-platform`
4. [ ] Verify rollback success
5. [ ] Restore database from backup (if necessary)
6. [ ] Update DNS/load balancer (if necessary)
7. [ ] Communicate rollback completion
8. [ ] Conduct post-incident review

## Emergency Procedures

### Service Outage
1. [ ] Check infrastructure status (cluster, database, network)
2. [ ] Review recent deployments and changes
3. [ ] Check application logs and metrics
4. [ ] Scale up resources if needed
5. [ ] Implement emergency fixes
6. [ ] Communicate status to stakeholders

### Database Issues
1. [ ] Check database connectivity and performance
2. [ ] Review database logs
3. [ ] Check for blocking queries or locks
4. [ ] Consider read-only mode if necessary
5. [ ] Restore from backup if corrupted

### Security Incident
1. [ ] Isolate affected systems
2. [ ] Review security logs and alerts
3. [ ] Rotate compromised credentials
4. [ ] Apply security patches
5. [ ] Conduct security audit
6. [ ] Document incident and lessons learned

## Validation Commands

### Health Checks
```bash
# Application health
curl -f https://yourdomain.com/health

# Kubernetes pod status
kubectl get pods -n api-translation-platform

# Service endpoints
kubectl get endpoints -n api-translation-platform

# Ingress status
kubectl get ingress -n api-translation-platform
```

### Performance Checks
```bash
# Resource utilization
kubectl top pods -n api-translation-platform

# HPA status
kubectl get hpa -n api-translation-platform

# Metrics endpoint
curl https://yourdomain.com/metrics
```

### Database Checks
```bash
# Database connectivity
kubectl exec -it deployment/api-translation-platform -n api-translation-platform -- \
  psql -h $DATABASE_HOST -U $DATABASE_USER -d $DATABASE_NAME -c "SELECT 1;"

# Database performance
kubectl exec -it postgres-pod -- \
  psql -U postgres -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"
```

### Backup Verification
```bash
# Test backup script
./scripts/backup.sh

# Verify backup files
ls -la /backups/

# Test recovery (in staging environment)
./scripts/recovery.sh latest
```

## Sign-off

### Technical Lead
- [ ] All technical requirements are met
- [ ] Code review is complete
- [ ] Tests are passing
- [ ] Documentation is updated

**Signature:** _________________ **Date:** _________

### DevOps Engineer
- [ ] Infrastructure is ready
- [ ] Monitoring is configured
- [ ] Backup procedures are tested
- [ ] Security requirements are met

**Signature:** _________________ **Date:** _________

### Security Officer
- [ ] Security scan is complete
- [ ] Vulnerabilities are addressed
- [ ] Access controls are configured
- [ ] Compliance requirements are met

**Signature:** _________________ **Date:** _________

### Product Owner
- [ ] Business requirements are met
- [ ] User acceptance testing is complete
- [ ] Rollback plan is approved
- [ ] Go-live approval granted

**Signature:** _________________ **Date:** _________