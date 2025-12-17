#!/bin/bash

# API Translation Platform Backup Script
# This script creates backups of the database and configuration

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS="${RETENTION_DAYS:-30}"

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

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Database backup
log "Starting database backup..."
PGPASSWORD="$DB_PASSWORD" pg_dump \
    -h "$DB_HOST" \
    -p "$DB_PORT" \
    -U "$DB_USER" \
    -d "$DB_NAME" \
    --verbose \
    --no-password \
    --format=custom \
    --compress=9 \
    > "$BACKUP_DIR/database_${TIMESTAMP}.dump"

if [ $? -eq 0 ]; then
    log "Database backup completed successfully"
else
    log "Database backup failed"
    exit 1
fi

# Configuration backup (if running in Kubernetes)
if command -v kubectl &> /dev/null; then
    log "Starting configuration backup..."
    
    # Backup ConfigMaps
    kubectl get configmap api-translation-platform-config -n api-translation-platform -o yaml > "$BACKUP_DIR/configmap_${TIMESTAMP}.yaml"
    
    # Backup Secrets
    kubectl get secrets -n api-translation-platform -o yaml > "$BACKUP_DIR/secrets_${TIMESTAMP}.yaml"
    
    # Backup deployment manifests
    kubectl get deployment api-translation-platform -n api-translation-platform -o yaml > "$BACKUP_DIR/deployment_${TIMESTAMP}.yaml"
    
    log "Configuration backup completed"
fi

# Create backup archive
log "Creating backup archive..."
tar -czf "$BACKUP_DIR/backup_${TIMESTAMP}.tar.gz" \
    -C "$BACKUP_DIR" \
    "database_${TIMESTAMP}.dump" \
    $([ -f "$BACKUP_DIR/configmap_${TIMESTAMP}.yaml" ] && echo "configmap_${TIMESTAMP}.yaml") \
    $([ -f "$BACKUP_DIR/secrets_${TIMESTAMP}.yaml" ] && echo "secrets_${TIMESTAMP}.yaml") \
    $([ -f "$BACKUP_DIR/deployment_${TIMESTAMP}.yaml" ] && echo "deployment_${TIMESTAMP}.yaml")

# Upload to S3 if configured
if [ -n "$S3_BUCKET" ]; then
    log "Uploading backup to S3..."
    if command -v aws &> /dev/null; then
        aws s3 cp "$BACKUP_DIR/backup_${TIMESTAMP}.tar.gz" "s3://$S3_BUCKET/backups/" --region "$S3_REGION"
        log "Backup uploaded to S3 successfully"
    else
        log "AWS CLI not found, skipping S3 upload"
    fi
fi

# Cleanup old backups
log "Cleaning up old backups..."
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "database_*.dump" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "configmap_*.yaml" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "secrets_*.yaml" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "deployment_*.yaml" -mtime +$RETENTION_DAYS -delete

# Cleanup S3 old backups if configured
if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
    log "Cleaning up old S3 backups..."
    aws s3 ls "s3://$S3_BUCKET/backups/" --region "$S3_REGION" | \
    while read -r line; do
        createDate=$(echo "$line" | awk '{print $1" "$2}')
        createDate=$(date -d "$createDate" +%s)
        olderThan=$(date -d "$RETENTION_DAYS days ago" +%s)
        if [[ $createDate -lt $olderThan ]]; then
            fileName=$(echo "$line" | awk '{print $4}')
            if [[ $fileName != "" ]]; then
                aws s3 rm "s3://$S3_BUCKET/backups/$fileName" --region "$S3_REGION"
            fi
        fi
    done
fi

log "Backup process completed successfully"
log "Backup file: $BACKUP_DIR/backup_${TIMESTAMP}.tar.gz"