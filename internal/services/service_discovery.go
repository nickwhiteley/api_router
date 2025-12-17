package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/go-redis/redis/v8"
)

// ServiceDiscoveryService handles service registration and discovery
type ServiceDiscoveryService interface {
	Register(ctx context.Context) error
	Deregister(ctx context.Context) error
	GetHealthyInstances(ctx context.Context) ([]*models.ServiceInstance, error)
	StartHeartbeat(ctx context.Context) error
	StopHeartbeat() error
	GetInstanceID() string
}

type serviceDiscoveryService struct {
	config     *config.Config
	logger     *logger.Logger
	redis      *redis.Client
	instanceID string
	hostname   string
	ipAddress  string

	heartbeatTicker *time.Ticker
	heartbeatDone   chan bool
	mu              sync.RWMutex
}

// NewServiceDiscoveryService creates a new service discovery service
func NewServiceDiscoveryService(
	config *config.Config,
	logger *logger.Logger,
	redis *redis.Client,
) ServiceDiscoveryService {
	hostname, _ := os.Hostname()
	ipAddress := getLocalIP()
	instanceID := fmt.Sprintf("%s-%s-%d", hostname, ipAddress, time.Now().Unix())

	return &serviceDiscoveryService{
		config:        config,
		logger:        logger,
		redis:         redis,
		instanceID:    instanceID,
		hostname:      hostname,
		ipAddress:     ipAddress,
		heartbeatDone: make(chan bool),
	}
}

// Register registers this service instance with the discovery service
func (s *serviceDiscoveryService) Register(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	instance := &models.ServiceInstance{
		ID:            s.instanceID,
		Hostname:      s.hostname,
		IPAddress:     s.ipAddress,
		Port:          s.config.Server.Port,
		Status:        models.ServiceStatusHealthy,
		RegisteredAt:  time.Now(),
		LastHeartbeat: time.Now(),
		Metadata: map[string]string{
			"version": "1.0.0",
			"region":  os.Getenv("REGION"),
			"zone":    os.Getenv("ZONE"),
		},
	}

	instanceData, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("failed to marshal instance data: %w", err)
	}

	// Register instance in Redis with TTL
	key := fmt.Sprintf("services:api-translation-platform:instances:%s", s.instanceID)
	err = s.redis.Set(ctx, key, instanceData, time.Duration(s.config.ServiceDiscovery.HeartbeatInterval*3)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("failed to register service instance: %w", err)
	}

	// Add to active instances set
	setKey := "services:api-translation-platform:active"
	err = s.redis.SAdd(ctx, setKey, s.instanceID).Err()
	if err != nil {
		return fmt.Errorf("failed to add to active instances: %w", err)
	}

	s.logger.WithFields(map[string]interface{}{
		"instance_id": s.instanceID,
		"hostname":    s.hostname,
		"ip_address":  s.ipAddress,
		"port":        s.config.Server.Port,
	}).Info("Service instance registered")

	return nil
}

// Deregister removes this service instance from the discovery service
func (s *serviceDiscoveryService) Deregister(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove from active instances set
	setKey := "services:api-translation-platform:active"
	err := s.redis.SRem(ctx, setKey, s.instanceID).Err()
	if err != nil {
		s.logger.WithError(err).Warn("Failed to remove from active instances set")
	}

	// Remove instance data
	key := fmt.Sprintf("services:api-translation-platform:instances:%s", s.instanceID)
	err = s.redis.Del(ctx, key).Err()
	if err != nil {
		s.logger.WithError(err).Warn("Failed to remove instance data")
	}

	s.logger.WithField("instance_id", s.instanceID).Info("Service instance deregistered")

	return nil
}

// GetHealthyInstances returns all healthy service instances
func (s *serviceDiscoveryService) GetHealthyInstances(ctx context.Context) ([]*models.ServiceInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get all active instance IDs
	setKey := "services:api-translation-platform:active"
	instanceIDs, err := s.redis.SMembers(ctx, setKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get active instances: %w", err)
	}

	var instances []*models.ServiceInstance
	for _, instanceID := range instanceIDs {
		key := fmt.Sprintf("services:api-translation-platform:instances:%s", instanceID)
		instanceData, err := s.redis.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				// Instance expired, remove from active set
				s.redis.SRem(ctx, setKey, instanceID)
				continue
			}
			s.logger.WithError(err).WithField("instance_id", instanceID).Warn("Failed to get instance data")
			continue
		}

		var instance models.ServiceInstance
		if err := json.Unmarshal([]byte(instanceData), &instance); err != nil {
			s.logger.WithError(err).WithField("instance_id", instanceID).Warn("Failed to unmarshal instance data")
			continue
		}

		// Check if instance is still healthy (heartbeat within expected interval)
		if time.Since(instance.LastHeartbeat) > time.Duration(s.config.ServiceDiscovery.HeartbeatInterval*3)*time.Second {
			instance.Status = models.ServiceStatusUnhealthy
		}

		instances = append(instances, &instance)
	}

	return instances, nil
}

// StartHeartbeat starts sending periodic heartbeats
func (s *serviceDiscoveryService) StartHeartbeat(ctx context.Context) error {
	// Check if service discovery is enabled
	if !s.config.ServiceDiscovery.Enabled {
		s.logger.Info("Service discovery is disabled, skipping heartbeat")
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.heartbeatTicker != nil {
		return fmt.Errorf("heartbeat already started")
	}

	interval := time.Duration(s.config.ServiceDiscovery.HeartbeatInterval) * time.Second
	s.heartbeatTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-s.heartbeatTicker.C:
				if err := s.sendHeartbeat(ctx); err != nil {
					s.logger.WithError(err).Error("Failed to send heartbeat")
				}
			case <-s.heartbeatDone:
				return
			}
		}
	}()

	s.logger.WithField("interval", interval).Info("Heartbeat started")
	return nil
}

// StopHeartbeat stops sending heartbeats
func (s *serviceDiscoveryService) StopHeartbeat() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.heartbeatTicker == nil {
		return nil
	}

	s.heartbeatTicker.Stop()
	s.heartbeatTicker = nil

	close(s.heartbeatDone)
	s.heartbeatDone = make(chan bool)

	s.logger.Info("Heartbeat stopped")
	return nil
}

// GetInstanceID returns the current instance ID
func (s *serviceDiscoveryService) GetInstanceID() string {
	return s.instanceID
}

// sendHeartbeat sends a heartbeat to update the instance's last seen time
func (s *serviceDiscoveryService) sendHeartbeat(ctx context.Context) error {
	// Create a timeout context for Redis operations
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	key := fmt.Sprintf("services:api-translation-platform:instances:%s", s.instanceID)

	// Get current instance data
	instanceData, err := s.redis.Get(timeoutCtx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// Instance not found, re-register
			return s.Register(timeoutCtx)
		}
		// Log error but don't fail the application
		s.logger.WithError(err).Warn("Redis operation failed during heartbeat, continuing without service discovery")
		return nil
	}

	var instance models.ServiceInstance
	if err := json.Unmarshal([]byte(instanceData), &instance); err != nil {
		return fmt.Errorf("failed to unmarshal instance data: %w", err)
	}

	// Update heartbeat time
	instance.LastHeartbeat = time.Now()
	instance.Status = models.ServiceStatusHealthy

	updatedData, err := json.Marshal(instance)
	if err != nil {
		return fmt.Errorf("failed to marshal updated instance data: %w", err)
	}

	// Update instance data with TTL
	err = s.redis.Set(ctx, key, updatedData, time.Duration(s.config.ServiceDiscovery.HeartbeatInterval*3)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("failed to update heartbeat: %w", err)
	}

	return nil
}

// getLocalIP gets the local IP address
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
