#!/bin/bash

# API Translation Platform Deployment Validation Script
# This script validates that a deployment is healthy and ready for production

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-api-translation-platform}"
TIMEOUT="${TIMEOUT:-300}"
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-http://localhost/health}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if kubectl is available and configured
check_kubectl() {
    log "Checking kubectl configuration..."
    
    if ! command -v kubectl &> /dev/null; then
        error "kubectl is not installed or not in PATH"
        return 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        error "kubectl is not configured or cluster is not accessible"
        return 1
    fi
    
    success "kubectl is configured and cluster is accessible"
}

# Check if namespace exists
check_namespace() {
    log "Checking namespace: $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        success "Namespace $NAMESPACE exists"
    else
        error "Namespace $NAMESPACE does not exist"
        return 1
    fi
}

# Check deployment status
check_deployment() {
    log "Checking deployment status..."
    
    local deployment="api-translation-platform"
    
    if ! kubectl get deployment "$deployment" -n "$NAMESPACE" &> /dev/null; then
        error "Deployment $deployment not found in namespace $NAMESPACE"
        return 1
    fi
    
    # Check if deployment is ready
    local ready_replicas=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}')
    local desired_replicas=$(kubectl get deployment "$deployment" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}')
    
    if [[ "$ready_replicas" == "$desired_replicas" ]]; then
        success "Deployment $deployment is ready ($ready_replicas/$desired_replicas replicas)"
    else
        error "Deployment $deployment is not ready ($ready_replicas/$desired_replicas replicas)"
        return 1
    fi
}

# Check pod status
check_pods() {
    log "Checking pod status..."
    
    local pods=$(kubectl get pods -n "$NAMESPACE" -l app=api-translation-platform -o jsonpath='{.items[*].metadata.name}')
    
    if [[ -z "$pods" ]]; then
        error "No pods found with label app=api-translation-platform"
        return 1
    fi
    
    local failed_pods=0
    for pod in $pods; do
        local status=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}')
        local ready=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
        
        if [[ "$status" == "Running" && "$ready" == "True" ]]; then
            success "Pod $pod is running and ready"
        else
            error "Pod $pod is not ready (status: $status, ready: $ready)"
            ((failed_pods++))
        fi
    done
    
    if [[ $failed_pods -gt 0 ]]; then
        return 1
    fi
}

# Check service endpoints
check_services() {
    log "Checking service endpoints..."
    
    local service="api-translation-platform-service"
    
    if ! kubectl get service "$service" -n "$NAMESPACE" &> /dev/null; then
        error "Service $service not found"
        return 1
    fi
    
    local endpoints=$(kubectl get endpoints "$service" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}')
    
    if [[ -n "$endpoints" ]]; then
        local endpoint_count=$(echo "$endpoints" | wc -w)
        success "Service $service has $endpoint_count endpoints: $endpoints"
    else
        error "Service $service has no endpoints"
        return 1
    fi
}

# Check ingress configuration
check_ingress() {
    log "Checking ingress configuration..."
    
    local ingress="api-translation-platform-ingress"
    
    if kubectl get ingress "$ingress" -n "$NAMESPACE" &> /dev/null; then
        local hosts=$(kubectl get ingress "$ingress" -n "$NAMESPACE" -o jsonpath='{.spec.rules[*].host}')
        success "Ingress $ingress is configured for hosts: $hosts"
    else
        warning "Ingress $ingress not found (may be using LoadBalancer service)"
    fi
}

# Check HPA status
check_hpa() {
    log "Checking Horizontal Pod Autoscaler..."
    
    local hpa="api-translation-platform-hpa"
    
    if kubectl get hpa "$hpa" -n "$NAMESPACE" &> /dev/null; then
        local current_replicas=$(kubectl get hpa "$hpa" -n "$NAMESPACE" -o jsonpath='{.status.currentReplicas}')
        local desired_replicas=$(kubectl get hpa "$hpa" -n "$NAMESPACE" -o jsonpath='{.status.desiredReplicas}')
        local min_replicas=$(kubectl get hpa "$hpa" -n "$NAMESPACE" -o jsonpath='{.spec.minReplicas}')
        local max_replicas=$(kubectl get hpa "$hpa" -n "$NAMESPACE" -o jsonpath='{.spec.maxReplicas}')
        
        success "HPA $hpa is active (current: $current_replicas, desired: $desired_replicas, range: $min_replicas-$max_replicas)"
    else
        warning "HPA $hpa not found"
    fi
}

# Check ConfigMap and Secrets
check_configuration() {
    log "Checking configuration..."
    
    local configmap="api-translation-platform-config"
    
    if kubectl get configmap "$configmap" -n "$NAMESPACE" &> /dev/null; then
        success "ConfigMap $configmap exists"
    else
        error "ConfigMap $configmap not found"
        return 1
    fi
    
    # Check for common secrets (optional)
    local secrets=("database-secret" "redis-secret" "jwt-secret")
    for secret in "${secrets[@]}"; do
        if kubectl get secret "$secret" -n "$NAMESPACE" &> /dev/null 2>&1; then
            success "Secret $secret exists"
        else
            warning "Secret $secret not found (may be configured differently)"
        fi
    done
}

# Check resource utilization
check_resources() {
    log "Checking resource utilization..."
    
    if command -v kubectl &> /dev/null && kubectl top nodes &> /dev/null; then
        local pods=$(kubectl get pods -n "$NAMESPACE" -l app=api-translation-platform -o jsonpath='{.items[*].metadata.name}')
        
        for pod in $pods; do
            local cpu=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $2}')
            local memory=$(kubectl top pod "$pod" -n "$NAMESPACE" --no-headers | awk '{print $3}')
            success "Pod $pod resource usage - CPU: $cpu, Memory: $memory"
        done
    else
        warning "Metrics server not available, skipping resource utilization check"
    fi
}

# Test health endpoints
test_health_endpoints() {
    log "Testing health endpoints..."
    
    # Test through port-forward if direct access is not available
    if [[ "$HEALTH_ENDPOINT" == "http://localhost"* ]]; then
        log "Setting up port-forward for health check..."
        kubectl port-forward service/api-translation-platform-service 8080:80 -n "$NAMESPACE" &
        local pf_pid=$!
        sleep 5
        
        # Test health endpoint
        if curl -f -s "http://localhost:8080/health" > /dev/null; then
            success "Health endpoint is responding"
        else
            error "Health endpoint is not responding"
            kill $pf_pid 2>/dev/null || true
            return 1
        fi
        
        # Test metrics endpoint
        if curl -f -s "http://localhost:8080/metrics" > /dev/null; then
            success "Metrics endpoint is responding"
        else
            warning "Metrics endpoint is not responding"
        fi
        
        kill $pf_pid 2>/dev/null || true
    else
        # Test external endpoint
        if curl -f -s "$HEALTH_ENDPOINT" > /dev/null; then
            success "External health endpoint is responding: $HEALTH_ENDPOINT"
        else
            error "External health endpoint is not responding: $HEALTH_ENDPOINT"
            return 1
        fi
    fi
}

# Check logs for errors
check_logs() {
    log "Checking recent logs for errors..."
    
    local pods=$(kubectl get pods -n "$NAMESPACE" -l app=api-translation-platform -o jsonpath='{.items[*].metadata.name}')
    local error_count=0
    
    for pod in $pods; do
        local errors=$(kubectl logs "$pod" -n "$NAMESPACE" --since=5m | grep -i "error\|fatal\|panic" | wc -l)
        if [[ $errors -gt 0 ]]; then
            warning "Pod $pod has $errors error messages in the last 5 minutes"
            ((error_count++))
        else
            success "Pod $pod has no recent error messages"
        fi
    done
    
    if [[ $error_count -gt 0 ]]; then
        warning "Found error messages in $error_count pods. Review logs manually."
    fi
}

# Main validation function
main() {
    log "Starting deployment validation for namespace: $NAMESPACE"
    echo "=================================================="
    
    local failed_checks=0
    
    # Run all checks
    check_kubectl || ((failed_checks++))
    check_namespace || ((failed_checks++))
    check_deployment || ((failed_checks++))
    check_pods || ((failed_checks++))
    check_services || ((failed_checks++))
    check_ingress # Don't fail on ingress issues
    check_hpa # Don't fail on HPA issues
    check_configuration || ((failed_checks++))
    check_resources # Don't fail on resource check issues
    test_health_endpoints || ((failed_checks++))
    check_logs # Don't fail on log warnings
    
    echo "=================================================="
    
    if [[ $failed_checks -eq 0 ]]; then
        success "All critical validation checks passed! Deployment appears healthy."
        log "Deployment validation completed successfully"
        exit 0
    else
        error "$failed_checks critical validation checks failed!"
        log "Deployment validation failed"
        exit 1
    fi
}

# Handle script arguments
case "${1:-validate}" in
    "validate")
        main
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [validate|help]"
        echo ""
        echo "Environment variables:"
        echo "  NAMESPACE        - Kubernetes namespace (default: api-translation-platform)"
        echo "  TIMEOUT          - Timeout in seconds (default: 300)"
        echo "  HEALTH_ENDPOINT  - Health endpoint URL (default: http://localhost/health)"
        echo ""
        echo "Examples:"
        echo "  $0                                    # Validate default deployment"
        echo "  NAMESPACE=staging $0                  # Validate staging deployment"
        echo "  HEALTH_ENDPOINT=https://api.example.com/health $0  # Test external endpoint"
        ;;
    *)
        error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac