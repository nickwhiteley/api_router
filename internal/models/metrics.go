package models

import (
	"time"

	"gorm.io/gorm"
)

// MetricType represents the type of metric being recorded
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// Metric represents a time-series metric data point
type Metric struct {
	ID             string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string         `json:"organisation_id" gorm:"type:uuid;index" validate:"required"`
	Name           string         `json:"name" gorm:"not null;index" validate:"required"`
	Type           MetricType     `json:"type" gorm:"not null" validate:"required"`
	Value          float64        `json:"value" gorm:"not null"`
	Labels         JSONMap        `json:"labels" gorm:"type:jsonb"`
	Timestamp      time.Time      `json:"timestamp" gorm:"not null;index"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
}

// TableName returns the table name for Metric
func (Metric) TableName() string {
	return "metrics"
}

// HealthStatus represents the health status of a system component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthCheck represents a health check result
type HealthCheck struct {
	ID        string                 `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Component string                 `json:"component" gorm:"not null;index" validate:"required"`
	Status    HealthStatus           `json:"status" gorm:"not null" validate:"required"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details" gorm:"type:jsonb"`
	Duration  int64                  `json:"duration"` // in milliseconds
	Timestamp time.Time              `json:"timestamp" gorm:"not null;index"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	DeletedAt gorm.DeletedAt         `json:"-" gorm:"index"`
}

// TableName returns the table name for HealthCheck
func (HealthCheck) TableName() string {
	return "health_checks"
}

// IsHealthy returns true if the health check status is healthy
func (h *HealthCheck) IsHealthy() bool {
	return h.Status == HealthStatusHealthy
}

// SystemMetrics represents aggregated system metrics
type SystemMetrics struct {
	RequestsPerSecond   float64            `json:"requests_per_second"`
	AverageResponseTime float64            `json:"average_response_time"`
	ErrorRate           float64            `json:"error_rate"`
	SuccessRate         float64            `json:"success_rate"`
	CPUUsage            float64            `json:"cpu_usage"`
	MemoryUsage         float64            `json:"memory_usage"`
	NetworkBytesIn      int64              `json:"network_bytes_in"`
	NetworkBytesOut     int64              `json:"network_bytes_out"`
	ActiveConnections   int                `json:"active_connections"`
	TotalRequests       int64              `json:"total_requests"`
	TotalErrors         int64              `json:"total_errors"`
	OrganisationMetrics map[string]float64 `json:"organisation_metrics,omitempty"`
	Timestamp           time.Time          `json:"timestamp"`
}

// ThroughputMetrics represents throughput-specific metrics
type ThroughputMetrics struct {
	OrganisationID      string    `json:"organisation_id"`
	ConnectorID         string    `json:"connector_id,omitempty"`
	RequestCount        int64     `json:"request_count"`
	SuccessCount        int64     `json:"success_count"`
	ErrorCount          int64     `json:"error_count"`
	AverageResponseTime float64   `json:"average_response_time"`
	MinResponseTime     float64   `json:"min_response_time"`
	MaxResponseTime     float64   `json:"max_response_time"`
	P95ResponseTime     float64   `json:"p95_response_time"`
	P99ResponseTime     float64   `json:"p99_response_time"`
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
}

// Alert represents an alert condition
type Alert struct {
	ID             string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string         `json:"organisation_id" gorm:"type:uuid;index"`
	Name           string         `json:"name" gorm:"not null" validate:"required"`
	Condition      string         `json:"condition" gorm:"not null" validate:"required"`
	Threshold      float64        `json:"threshold" gorm:"not null"`
	Severity       string         `json:"severity" gorm:"not null" validate:"required"`
	IsActive       bool           `json:"is_active" gorm:"default:true"`
	LastTriggered  *time.Time     `json:"last_triggered,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
}

// TableName returns the table name for Alert
func (Alert) TableName() string {
	return "alerts"
}
