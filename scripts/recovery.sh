#!/bin/bash

# API Translation Platform Recovery Script
# This script restores backups of the database and configuration

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
RESTORE_FILE="${1:-}"

# Database configuration
DB_HOST="${DATABASE_HOST:-localhost}"
DB_PORT="${DATABASE_PORT:-5432}"
DB_NAME="${DATABASE_NAME:-api_translation_platform}"
DB_USER="${DATABASE_USER:-postgres}"
DB_PASSWORD="${DATABASE_PASSWORD:-postgres}"

# S3 configuration (optional)
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
S3_REGION="${BACKUP_S3_REGION:-us-west-2}"

# Logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Usage function
usage() {
    echo "Usage: $0 [backup_file.tar.gz|s3://bucket/path/backup_file.tar.gz|latest]"
    echo ""
    echo "Examples:"
    echo "  $0 /backups/backup_20231201_120000.tar.gz"
    echo "  $0 s3://my-bucket/backups/backup_20231201_120000.tar.gz"
    echo "  $0 latest"
    exit 1
}

# Validate input
if [ -z "$RESTORE_FILE" ]; then
    usage
fi

# Create temporary directory for extraction
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Download/locate backup file
if [ "$RESTORE_FILE" = "latest" ]; then
    log "Finding latest backup..."
    if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
        # Find latest backup in S3
        LATEST_BACKUP=$(aws s3 ls "s3://$S3_BUCKET/backups/" --region "$S3_REGION" | sort | tail -n 1 | awk '{print $4}')
        if [ -n "$LATEST_BACKUP" ]; then
            RESTORE_FILE="s3://$S3_BUCKET/backups/$LATEST_BACKUP"
            log "Latest backup found: $RESTORE_FILE"
        else
            log "No backups found in S3"
            exit 1
        fi
    else
        # Find latest local backup
        LATEST_BACKUP=$(find "$BACKUP_DIR" -name "backup_*.tar.gz" -type f -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
        if [ -n "$LATEST_BACKUP" ]; then
            RESTORE_FILE="$LATEST_BACKUP"
            log "Latest backup found: $RESTORE_FILE"
        else
            log "No local backups found"
            exit 1
        fi
    fi
fi

# Download from S3 if needed
if [[ "$RESTORE_FILE" == s3://* ]]; then
    log "Downloading backup from S3..."
    if command -v aws &> /dev/null; then
        BACKUP_FILE="$TEMP_DIR/$(basename "$RESTORE_FILE")"
        aws s3 cp "$RESTORE_FILE" "$BACKUP_FILE" --region "$S3_REGION"
        RESTORE_FILE="$BACKUP_FILE"
        log "Backup downloaded successfully"
    else
        log "AWS CLI not found, cannot download from S3"
        exit 1
    fi
fi

# Verify backup file exists
if [ ! -f "$RESTORE_FILE" ]; then
    log "Backup file not found: $RESTORE_FILE"
    exit 1
fi

# Extract backup
log "Extracting backup archive..."
tar -xzf "$RESTORE_FILE" -C "$TEMP_DIR"

# Find database dump file
DB_DUMP=$(find "$TEMP_DIR" -name "database_*.dump" | head -1)
if [ -z "$DB_DUMP" ]; then
    log "No database dump found in backup"
    exit 1
fi

# Confirm restoration
echo "WARNING: This will restore the database and potentially overwrite existing data."
echo "Backup file: $RESTORE_FILE"
echo "Database: $DB_NAME on $DB_HOST:$DB_PORT"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    log "Recovery cancelled by user"
    exit 0
fi

# Stop application if running in Kubernetes
if command -v kubectl &> /dev/null; then
    log "Scaling down application..."
    kubectl scale deployment api-translation-platform --replicas=0 -n api-translation-platform || true
    kubectl wait --for=delete pod -l app=api-translation-platform -n api-translation-platform --timeout=300s || true
fi

# Create database backup before restore
log "Creating safety backup of current database..."
SAFETY_BACKUP="$BACKUP_DIR/safety_backup_$(date +%Y%m%d_%H%M%S).dump"
PGPASSWORD="$DB_PASSWORD" pg_dump \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --verbose \
    --no-password \
    --format=custom \
    --compress=9 \
    > "$SAFETY_BACKUP" || log "Warning: Could not create safety backup"

# Drop and recreate database
log "Recreating database..."
PGPASSWORD="$DB_PASSWORD" dropdb \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    --if-exists \
    "$DB_NAME"

PGPASSWORD="$DB_PASSWORD" createdb \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    "$DB_NAME"

# Restore database
log "Restoring database from backup..."
PGPASSWORD="$DB_PASSWORD" pg_restore \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --verbose \
    --no-password \
    --clean \
    --if-exists \
    "$DB_DUMP"

if [ $? -eq 0 ]; then
    log "Database restore completed successfully"
else
    log "Database restore failed"
    
    # Attempt to restore safety backup
    if [ -f "$SAFETY_BACKUP" ]; then
        log "Attempting to restore safety backup..."
        PGPASSWORD="$DB_PASSWORD" dropdb \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            --if-exists \
            "$DB_NAME"
        
        PGPASSWORD="$DB_PASSWORD" createdb \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            "$DB_NAME"
        
        PGPASSWORD="$DB_PASSWORD" pg_restore \
            -h "$DB_HOST" \
            -p "$DB_PORT" \
            -U "$DB_USER" \
            -d "$DB_NAME" \
            --verbose \
            --no-password \
            --clean \
            --if-exists \
            "$SAFETY_BACKUP"
    fi
    
    exit 1
fi

# Restore Kubernetes configurations if available
CONFIGMAP_FILE=$(find "$TEMP_DIR" -name "configmap_*.yaml" | head -1)
SECRETS_FILE=$(find "$TEMP_DIR" -name "secrets_*.yaml" | head -1)
DEPLOYMENT_FILE=$(find "$TEMP_DIR" -name "deployment_*.yaml" | head -1)

if command -v kubectl &> /dev/null; then
    if [ -f "$CONFIGMAP_FILE" ]; then
        log "Restoring ConfigMap..."
        kubectl apply -f "$CONFIGMAP_FILE"
    fi
    
    if [ -f "$SECRETS_FILE" ]; then
        log "Restoring Secrets..."
        kubectl apply -f "$SECRETS_FILE"
    fi
    
    if [ -f "$DEPLOYMENT_FILE" ]; then
        log "Restoring Deployment configuration..."
        kubectl apply -f "$DEPLOYMENT_FILE"
    fi
    
    # Scale application back up
    log "Scaling application back up..."
    kubectl scale deployment api-translation-platform --replicas=3 -n api-translation-platform
    kubectl rollout status deployment/api-translation-platform -n api-translation-platform --timeout=600s
fi

# Verify restoration
log "Verifying restoration..."
if command -v kubectl &> /dev/null; then
    # Wait for pods to be ready
    kubectl wait --for=condition=ready pod -l app=api-translation-platform -n api-translation-platform --timeout=300s
    
    # Test health endpoint
    kubectl port-forward svc/api-translation-platform-service 8080:80 -n api-translation-platform &
    PF_PID=$!
    sleep 10
    
    if curl -f http://localhost:8080/health; then
        log "Health check passed - restoration successful"
    else
        log "Health check failed - restoration may have issues"
    fi
    
    kill $PF_PID 2>/dev/null || true
else
    # Direct database connection test
    PGPASSWORD="$DB_PASSWORD" psql \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" > /dev/null
    
    if [ $? -eq 0 ]; then
        log "Database connection test passed - restoration successful"
    else
        log "Database connection test failed - restoration may have issues"
    fi
fi

log "Recovery process completed"
log "Safety backup created at: $SAFETY_BACKUP"