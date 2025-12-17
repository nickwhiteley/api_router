package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/go-redis/redis/v8"
)

// DistributedConfigService handles distributed configuration management with consensus
type DistributedConfigService interface {
	SyncConfiguration(ctx context.Context) error
	StartConfigSync(ctx context.Context) error
	StopConfigSync() error
	ElectLeader(ctx context.Context) (bool, error)
	IsLeader() bool
	GetLeaderID() string
	BroadcastConfigChange(ctx context.Context, changeType string, data interface{}) error
	RegisterConfigChangeHandler(handler ConfigChangeHandler)
}

// ConfigChangeHandler handles configuration changes
type ConfigChangeHandler func(ctx context.Context, changeType string, data interface{}) error

type distributedConfigService struct {
	config           *config.Config
	logger           *logger.Logger
	redis            *redis.Client
	serviceDiscovery ServiceDiscoveryService
	configService    ConfigurationService

	isLeader       bool
	leaderID       string
	syncTicker     *time.Ticker
	syncDone       chan bool
	changeHandlers []ConfigChangeHandler
	mu             sync.RWMutex
}

// NewDistributedConfigService creates a new distributed configuration service
func NewDistributedConfigService(
	config *config.Config,
	logger *logger.Logger,
	redis *redis.Client,
	serviceDiscovery ServiceDiscoveryService,
	configService ConfigurationService,
) DistributedConfigService {
	return &distributedConfigService{
		config:           config,
		logger:           logger,
		redis:            redis,
		serviceDiscovery: serviceDiscovery,
		configService:    configService,
		syncDone:         make(chan bool),
		changeHandlers:   make([]ConfigChangeHandler, 0),
	}
}

// SyncConfiguration synchronizes configuration from the distributed store
func (d *distributedConfigService) SyncConfiguration(ctx context.Context) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Create a timeout context for Redis operations
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Get the latest configuration version from Redis
	versionKey := "config:version"
	currentVersion, err := d.redis.Get(timeoutCtx, versionKey).Result()
	if err != nil && err != redis.Nil {
		// Log error but don't fail the application
		d.logger.WithError(err).Warn("Redis operation failed during config sync, continuing with local config")
		return nil
	}

	// Get local configuration checksum (using organisation ID as a proxy for version)
	localChecksum, err := d.configService.GetConfigurationChecksum(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to get local config checksum: %w", err)
	}

	// If versions match, no sync needed
	if currentVersion == localChecksum {
		d.logger.Debug("Configuration is up to date")
		return nil
	}

	// Sync different configuration types
	if err := d.syncAPIConfigurations(ctx); err != nil {
		return fmt.Errorf("failed to sync API configurations: %w", err)
	}

	if err := d.syncConnectors(ctx); err != nil {
		return fmt.Errorf("failed to sync connectors: %w", err)
	}

	if err := d.syncOrganisations(ctx); err != nil {
		return fmt.Errorf("failed to sync organisations: %w", err)
	}

	// Synchronize configuration with the instance
	if err := d.configService.SynchronizeConfiguration(ctx, d.serviceDiscovery.GetInstanceID()); err != nil {
		return fmt.Errorf("failed to synchronize configuration: %w", err)
	}

	d.logger.WithFields(map[string]interface{}{
		"old_checksum": localChecksum,
		"new_version":  currentVersion,
	}).Info("Configuration synchronized")

	return nil
}

// StartConfigSync starts periodic configuration synchronization
func (d *distributedConfigService) StartConfigSync(ctx context.Context) error {
	// Check if clustering is enabled
	if !d.config.Clustering.Enabled {
		d.logger.Info("Clustering is disabled, skipping config sync")
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.syncTicker != nil {
		return fmt.Errorf("config sync already started")
	}

	interval := time.Duration(d.config.Clustering.ConfigSyncInterval) * time.Second
	d.syncTicker = time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-d.syncTicker.C:
				if err := d.SyncConfiguration(ctx); err != nil {
					d.logger.WithError(err).Error("Failed to sync configuration")
				}

				// Try to elect leader if not already leader
				if !d.isLeader {
					if elected, err := d.ElectLeader(ctx); err != nil {
						d.logger.WithError(err).Error("Failed to elect leader")
					} else if elected {
						d.logger.Info("Elected as configuration leader")
					}
				}

			case <-d.syncDone:
				return
			}
		}
	}()

	d.logger.WithField("interval", interval).Info("Configuration sync started")
	return nil
}

// StopConfigSync stops configuration synchronization
func (d *distributedConfigService) StopConfigSync() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.syncTicker == nil {
		return nil
	}

	d.syncTicker.Stop()
	d.syncTicker = nil

	close(d.syncDone)
	d.syncDone = make(chan bool)

	// Release leadership if we are the leader
	if d.isLeader {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d.releaseLeadership(ctx)
	}

	d.logger.Info("Configuration sync stopped")
	return nil
}

// ElectLeader attempts to elect this instance as the configuration leader
func (d *distributedConfigService) ElectLeader(ctx context.Context) (bool, error) {
	leaderKey := "config:leader"
	instanceID := d.serviceDiscovery.GetInstanceID()

	// Try to acquire leadership with TTL
	ttl := time.Duration(d.config.Clustering.LeaderElectionTimeout) * time.Second
	result, err := d.redis.SetNX(ctx, leaderKey, instanceID, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to acquire leadership: %w", err)
	}

	if result {
		d.mu.Lock()
		d.isLeader = true
		d.leaderID = instanceID
		d.mu.Unlock()

		// Start leadership renewal
		go d.renewLeadership(ctx)

		d.logger.WithField("instance_id", instanceID).Info("Acquired configuration leadership")
		return true, nil
	}

	// Get current leader
	currentLeader, err := d.redis.Get(ctx, leaderKey).Result()
	if err != nil && err != redis.Nil {
		return false, fmt.Errorf("failed to get current leader: %w", err)
	}

	d.mu.Lock()
	d.isLeader = false
	d.leaderID = currentLeader
	d.mu.Unlock()

	return false, nil
}

// IsLeader returns true if this instance is the configuration leader
func (d *distributedConfigService) IsLeader() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.isLeader
}

// GetLeaderID returns the current leader instance ID
func (d *distributedConfigService) GetLeaderID() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.leaderID
}

// BroadcastConfigChange broadcasts a configuration change to all instances
func (d *distributedConfigService) BroadcastConfigChange(ctx context.Context, changeType string, data interface{}) error {
	if !d.IsLeader() {
		return fmt.Errorf("only leader can broadcast configuration changes")
	}

	change := map[string]interface{}{
		"type":      changeType,
		"data":      data,
		"timestamp": time.Now(),
		"leader_id": d.serviceDiscovery.GetInstanceID(),
	}

	changeData, err := json.Marshal(change)
	if err != nil {
		return fmt.Errorf("failed to marshal config change: %w", err)
	}

	// Publish to Redis pub/sub
	channel := "config:changes"
	err = d.redis.Publish(ctx, channel, changeData).Err()
	if err != nil {
		return fmt.Errorf("failed to publish config change: %w", err)
	}

	// Update configuration version
	newVersion := fmt.Sprintf("%d", time.Now().Unix())
	versionKey := "config:version"
	err = d.redis.Set(ctx, versionKey, newVersion, 0).Err()
	if err != nil {
		return fmt.Errorf("failed to update config version: %w", err)
	}

	d.logger.WithFields(map[string]interface{}{
		"change_type": changeType,
		"version":     newVersion,
	}).Info("Configuration change broadcasted")

	return nil
}

// RegisterConfigChangeHandler registers a handler for configuration changes
func (d *distributedConfigService) RegisterConfigChangeHandler(handler ConfigChangeHandler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.changeHandlers = append(d.changeHandlers, handler)
}

// renewLeadership periodically renews leadership
func (d *distributedConfigService) renewLeadership(ctx context.Context) {
	leaderKey := "config:leader"
	instanceID := d.serviceDiscovery.GetInstanceID()
	ttl := time.Duration(d.config.Clustering.LeaderElectionTimeout) * time.Second
	renewInterval := ttl / 3 // Renew at 1/3 of TTL

	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if we're still the leader
			currentLeader, err := d.redis.Get(ctx, leaderKey).Result()
			if err != nil || currentLeader != instanceID {
				d.mu.Lock()
				d.isLeader = false
				d.mu.Unlock()
				d.logger.Warn("Lost configuration leadership")
				return
			}

			// Renew leadership
			err = d.redis.Expire(ctx, leaderKey, ttl).Err()
			if err != nil {
				d.logger.WithError(err).Error("Failed to renew leadership")
				d.mu.Lock()
				d.isLeader = false
				d.mu.Unlock()
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

// releaseLeadership releases leadership
func (d *distributedConfigService) releaseLeadership(ctx context.Context) {
	leaderKey := "config:leader"
	instanceID := d.serviceDiscovery.GetInstanceID()

	// Use Lua script to safely release leadership
	script := `
		if redis.call("GET", KEYS[1]) == ARGV[1] then
			return redis.call("DEL", KEYS[1])
		else
			return 0
		end
	`

	err := d.redis.Eval(ctx, script, []string{leaderKey}, instanceID).Err()
	if err != nil {
		d.logger.WithError(err).Error("Failed to release leadership")
	}

	d.mu.Lock()
	d.isLeader = false
	d.leaderID = ""
	d.mu.Unlock()
}

// syncAPIConfigurations synchronizes API configurations
func (d *distributedConfigService) syncAPIConfigurations(ctx context.Context) error {
	// Get API configurations from Redis
	pattern := "config:api:*"
	keys, err := d.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get API config keys: %w", err)
	}

	for _, key := range keys {
		configData, err := d.redis.Get(ctx, key).Result()
		if err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to get API config")
			continue
		}

		var apiConfig models.APIConfiguration
		if err := json.Unmarshal([]byte(configData), &apiConfig); err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to unmarshal API config")
			continue
		}

		// Update local configuration
		if _, err := d.configService.UpdateAPIConfiguration(ctx, &apiConfig); err != nil {
			d.logger.WithError(err).WithField("api_id", apiConfig.ID).Warn("Failed to update local API config")
		}
	}

	return nil
}

// syncConnectors synchronizes connector configurations
func (d *distributedConfigService) syncConnectors(ctx context.Context) error {
	// Get connectors from Redis
	pattern := "config:connector:*"
	keys, err := d.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get connector keys: %w", err)
	}

	for _, key := range keys {
		connectorData, err := d.redis.Get(ctx, key).Result()
		if err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to get connector config")
			continue
		}

		var connector models.Connector
		if err := json.Unmarshal([]byte(connectorData), &connector); err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to unmarshal connector config")
			continue
		}

		// Update local configuration
		if _, err := d.configService.UpdateConnector(ctx, &connector); err != nil {
			d.logger.WithError(err).WithField("connector_id", connector.ID).Warn("Failed to update local connector config")
		}
	}

	return nil
}

// syncOrganisations synchronizes organisation configurations
func (d *distributedConfigService) syncOrganisations(ctx context.Context) error {
	// Get organisations from Redis
	pattern := "config:org:*"
	keys, err := d.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get organisation keys: %w", err)
	}

	for _, key := range keys {
		orgData, err := d.redis.Get(ctx, key).Result()
		if err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to get organisation config")
			continue
		}

		var org models.Organisation
		if err := json.Unmarshal([]byte(orgData), &org); err != nil {
			d.logger.WithError(err).WithField("key", key).Warn("Failed to unmarshal organisation config")
			continue
		}

		// Update local configuration
		if _, err := d.configService.UpdateOrganisation(ctx, &org); err != nil {
			d.logger.WithError(err).WithField("org_id", org.ID).Warn("Failed to update local organisation config")
		}
	}

	return nil
}
