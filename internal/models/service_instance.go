package models

import (
	"time"
)

// ServiceStatus represents the status of a service instance
type ServiceStatus string

const (
	ServiceStatusHealthy   ServiceStatus = "healthy"
	ServiceStatusUnhealthy ServiceStatus = "unhealthy"
	ServiceStatusStarting  ServiceStatus = "starting"
	ServiceStatusStopping  ServiceStatus = "stopping"
)

// ServiceInstance represents a service instance in the cluster
type ServiceInstance struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	IPAddress     string            `json:"ip_address"`
	Port          string            `json:"port"`
	Status        ServiceStatus     `json:"status"`
	RegisteredAt  time.Time         `json:"registered_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	Metadata      map[string]string `json:"metadata"`
}

// IsHealthy returns true if the service instance is healthy
func (si *ServiceInstance) IsHealthy() bool {
	return si.Status == ServiceStatusHealthy
}

// GetEndpoint returns the HTTP endpoint for this service instance
func (si *ServiceInstance) GetEndpoint() string {
	return "http://" + si.IPAddress + ":" + si.Port
}

// GetHealthCheckURL returns the health check URL for this service instance
func (si *ServiceInstance) GetHealthCheckURL() string {
	return si.GetEndpoint() + "/health"
}

// IsExpired checks if the service instance has expired based on heartbeat
func (si *ServiceInstance) IsExpired(heartbeatInterval time.Duration) bool {
	return time.Since(si.LastHeartbeat) > heartbeatInterval*3
}
