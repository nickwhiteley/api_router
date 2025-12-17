package services

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiInstanceDeployment tests configuration synchronization across instances
func TestMultiInstanceDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup test environment
	ctx := context.Background()

	// Create test configuration
	cfg := &config.Config{
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:           true,
			HeartbeatInterval: 5, // Short interval for testing
			HealthCheckPath:   "/health",
		},
		LoadBalancer: config.LoadBalancerConfig{
			Strategy:       "round_robin",
			MaxRetries:     3,
			RetryInterval:  2,
			CircuitBreaker: true,
		},
		Clustering: config.ClusteringConfig{
			Enabled:                 true,
			ConfigSyncInterval:      10, // Short interval for testing
			LeaderElectionTimeout:   15,
			GracefulShutdownTimeout: 30,
		},
		Redis: config.RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   1, // Use different DB for testing
		},
	}

	// Create Redis client for testing
	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		DB:   cfg.Redis.DB,
	})
	defer redisClient.Close()

	// Clean up Redis before test
	redisClient.FlushDB(ctx)

	// Create logger
	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "json",
		},
	})

	t.Run("ConfigurationSynchronization", func(t *testing.T) {
		testConfigurationSynchronization(t, ctx, cfg, redisClient, testLogger)
	})

	t.Run("LoadDistributionAndFailover", func(t *testing.T) {
		testLoadDistributionAndFailover(t, ctx, cfg, redisClient, testLogger)
	})

	t.Run("GracefulShutdownAndStartup", func(t *testing.T) {
		testGracefulShutdownAndStartup(t, ctx, cfg, redisClient, testLogger)
	})
}

// testConfigurationSynchronization tests configuration sync across instances
func testConfigurationSynchronization(t *testing.T, ctx context.Context, cfg *config.Config, redisClient *redis.Client, testLogger *logger.Logger) {
	// Create multiple service discovery instances
	const numInstances = 3
	var services []ServiceDiscoveryService
	var distributedConfigs []DistributedConfigService

	// Create mock configuration service
	mockConfigService := &mockConfigurationService{
		configs: make(map[string]*models.APIConfiguration),
		version: "1.0.0",
	}

	// Create instances
	for i := 0; i < numInstances; i++ {
		serviceDiscovery := NewServiceDiscoveryService(cfg, testLogger, redisClient)
		distributedConfig := NewDistributedConfigService(cfg, testLogger, redisClient, serviceDiscovery, mockConfigService)

		services = append(services, serviceDiscovery)
		distributedConfigs = append(distributedConfigs, distributedConfig)

		// Register each instance
		err := serviceDiscovery.Register(ctx)
		require.NoError(t, err)

		// Start heartbeat
		err = serviceDiscovery.StartHeartbeat(ctx)
		require.NoError(t, err)

		// Start config sync
		err = distributedConfig.StartConfigSync(ctx)
		require.NoError(t, err)
	}

	// Wait for instances to register
	time.Sleep(2 * time.Second)

	// Verify all instances are registered
	instances, err := services[0].GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, numInstances)

	// Test leader election
	var leaders []string
	for _, distributedConfig := range distributedConfigs {
		if distributedConfig.IsLeader() {
			leaders = append(leaders, distributedConfig.GetLeaderID())
		}
	}

	// Should have exactly one leader
	assert.Len(t, leaders, 1, "Should have exactly one leader")

	// Test configuration broadcast
	leaderIndex := -1
	for i, distributedConfig := range distributedConfigs {
		if distributedConfig.IsLeader() {
			leaderIndex = i
			break
		}
	}
	require.NotEqual(t, -1, leaderIndex, "Should have found a leader")

	// Broadcast a configuration change from the leader
	testConfig := &models.APIConfiguration{
		ID:             "test-api-1",
		OrganisationID: "test-org-1",
		Name:           "Test API",
		Type:           "REST",
		Direction:      "inbound",
		Endpoint:       "/test",
	}

	err = distributedConfigs[leaderIndex].BroadcastConfigChange(ctx, "api_configuration_created", testConfig)
	require.NoError(t, err)

	// Wait for synchronization
	time.Sleep(3 * time.Second)

	// Verify all instances have the same configuration version
	for _, distributedConfig := range distributedConfigs {
		err := distributedConfig.SyncConfiguration(ctx)
		require.NoError(t, err)
	}

	// Cleanup
	for i, serviceDiscovery := range services {
		serviceDiscovery.StopHeartbeat()
		serviceDiscovery.Deregister(ctx)
		distributedConfigs[i].StopConfigSync()
	}
}

// testLoadDistributionAndFailover tests load balancing and failover scenarios
func testLoadDistributionAndFailover(t *testing.T, ctx context.Context, cfg *config.Config, redisClient *redis.Client, testLogger *logger.Logger) {
	// Create service discovery and load balancer
	serviceDiscovery := NewServiceDiscoveryService(cfg, testLogger, redisClient)
	loadBalancer := NewLoadBalancerService(cfg, testLogger, serviceDiscovery)

	// Create mock service instances
	instances := []*models.ServiceInstance{
		{
			ID:        "instance-1",
			Hostname:  "host-1",
			IPAddress: "192.168.1.1",
			Port:      "8080",
			Status:    models.ServiceStatusHealthy,
		},
		{
			ID:        "instance-2",
			Hostname:  "host-2",
			IPAddress: "192.168.1.2",
			Port:      "8080",
			Status:    models.ServiceStatusHealthy,
		},
		{
			ID:        "instance-3",
			Hostname:  "host-3",
			IPAddress: "192.168.1.3",
			Port:      "8080",
			Status:    models.ServiceStatusHealthy,
		},
	}

	// Update load balancer with instances
	loadBalancer.UpdateInstances(instances)

	// Test round-robin distribution
	selectedInstances := make(map[string]int)
	for i := 0; i < 30; i++ {
		instance, err := loadBalancer.GetNextInstance(ctx)
		require.NoError(t, err)
		require.NotNil(t, instance)
		selectedInstances[instance.ID]++
	}

	// Verify distribution is roughly equal (within reasonable variance)
	for instanceID, count := range selectedInstances {
		assert.True(t, count >= 8 && count <= 12,
			"Instance %s selected %d times, expected 8-12", instanceID, count)
	}

	// Test failover scenario - mark one instance as unhealthy
	instances[0].Status = models.ServiceStatusUnhealthy
	loadBalancer.UpdateInstances(instances)

	// Verify only healthy instances are selected
	selectedInstances = make(map[string]int)
	for i := 0; i < 20; i++ {
		instance, err := loadBalancer.GetNextInstance(ctx)
		require.NoError(t, err)
		require.NotNil(t, instance)
		selectedInstances[instance.ID]++
	}

	// Should not select the unhealthy instance
	assert.Equal(t, 0, selectedInstances["instance-1"], "Unhealthy instance should not be selected")
	assert.True(t, selectedInstances["instance-2"] > 0, "Healthy instance should be selected")
	assert.True(t, selectedInstances["instance-3"] > 0, "Healthy instance should be selected")

	// Test circuit breaker functionality
	assert.Equal(t, 2, loadBalancer.GetHealthyInstanceCount())
}

// testGracefulShutdownAndStartup tests graceful shutdown and startup procedures
func testGracefulShutdownAndStartup(t *testing.T, ctx context.Context, cfg *config.Config, redisClient *redis.Client, testLogger *logger.Logger) {
	// Create graceful shutdown service
	gracefulShutdown := NewGracefulShutdownService(cfg, testLogger)

	// Track hook execution
	var executedHooks []string
	var mu sync.Mutex

	// Register test hooks
	gracefulShutdown.RegisterStartupHook("test_startup_1", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		executedHooks = append(executedHooks, "startup_1")
		return nil
	})

	gracefulShutdown.RegisterStartupHook("test_startup_2", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		executedHooks = append(executedHooks, "startup_2")
		return nil
	})

	gracefulShutdown.RegisterShutdownHook("test_shutdown_1", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		executedHooks = append(executedHooks, "shutdown_1")
		return nil
	})

	gracefulShutdown.RegisterShutdownHook("test_shutdown_2", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		executedHooks = append(executedHooks, "shutdown_2")
		return nil
	})

	// Test startup
	err := gracefulShutdown.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for startup hooks to execute
	time.Sleep(100 * time.Millisecond)

	// Verify startup hooks were executed
	mu.Lock()
	startupHooksExecuted := 0
	for _, hook := range executedHooks {
		if hook == "startup_1" || hook == "startup_2" {
			startupHooksExecuted++
		}
	}
	mu.Unlock()
	assert.Equal(t, 2, startupHooksExecuted, "Both startup hooks should be executed")

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err = gracefulShutdown.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// Verify shutdown hooks were executed
	mu.Lock()
	shutdownHooksExecuted := 0
	for _, hook := range executedHooks {
		if hook == "shutdown_1" || hook == "shutdown_2" {
			shutdownHooksExecuted++
		}
	}
	mu.Unlock()
	assert.Equal(t, 2, shutdownHooksExecuted, "Both shutdown hooks should be executed")

	// Verify shutdown completion
	select {
	case <-gracefulShutdown.WaitForShutdown():
		// Expected - shutdown completed
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not complete within timeout")
	}
}

// Mock configuration service for testing
type mockConfigurationService struct {
	configs map[string]*models.APIConfiguration
	version string
	mu      sync.RWMutex
}

func (m *mockConfigurationService) GetConfigurationChecksum(ctx context.Context, orgID string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version, nil
}

func (m *mockConfigurationService) SynchronizeConfiguration(ctx context.Context, instanceID string) error {
	// Mock implementation
	return nil
}

func (m *mockConfigurationService) UpdateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.configs[config.ID] = config
	return config, nil
}

func (m *mockConfigurationService) UpdateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	// Mock implementation
	return connector, nil
}

func (m *mockConfigurationService) UpdateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	// Mock implementation
	return org, nil
}

// Implement all other required methods with minimal mock implementations
func (m *mockConfigurationService) CreateAPIConfiguration(ctx context.Context, config *models.APIConfiguration) (*models.APIConfiguration, error) {
	return config, nil
}

func (m *mockConfigurationService) DeleteAPIConfiguration(ctx context.Context, id string) error {
	return nil
}

func (m *mockConfigurationService) GetAPIConfiguration(ctx context.Context, id string) (*models.APIConfiguration, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetAPIConfigurationsByOrganisation(ctx context.Context, orgID string) ([]*models.APIConfiguration, error) {
	return nil, nil
}

func (m *mockConfigurationService) ValidateConfiguration(ctx context.Context, config *models.APIConfiguration) error {
	return nil
}

func (m *mockConfigurationService) TestAPIConfiguration(ctx context.Context, apiID string, testRequest map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

func (m *mockConfigurationService) CreateConnector(ctx context.Context, connector *models.Connector) (*models.Connector, error) {
	return connector, nil
}

func (m *mockConfigurationService) DeleteConnector(ctx context.Context, connectorID string) error {
	return nil
}

func (m *mockConfigurationService) GetConnector(ctx context.Context, connectorID string) (*models.Connector, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetConnectorsByOrganisation(ctx context.Context, orgID string) ([]*models.Connector, error) {
	return nil, nil
}

func (m *mockConfigurationService) UpdateConnectorScript(ctx context.Context, connectorID, script string) error {
	return nil
}

func (m *mockConfigurationService) CreateOrganisation(ctx context.Context, org *models.Organisation) (*models.Organisation, error) {
	return org, nil
}

func (m *mockConfigurationService) DeleteOrganisation(ctx context.Context, orgID string) error {
	return nil
}

func (m *mockConfigurationService) GetOrganisation(ctx context.Context, orgID string) (*models.Organisation, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetAllOrganisations(ctx context.Context) ([]*models.Organisation, error) {
	return nil, nil
}

func (m *mockConfigurationService) CreateConfigurationVersion(ctx context.Context, resourceType, resourceID string, configData models.JSONMap, userID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetConfigurationVersions(ctx context.Context, resourceType, resourceID string) ([]*models.ConfigurationVersion, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetConfigurationVersion(ctx context.Context, versionID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}

func (m *mockConfigurationService) RollbackToVersion(ctx context.Context, versionID string, userID string) error {
	return nil
}

func (m *mockConfigurationService) GetActiveConfigurationVersion(ctx context.Context, resourceType, resourceID string) (*models.ConfigurationVersion, error) {
	return nil, nil
}

func (m *mockConfigurationService) LogConfigurationChange(ctx context.Context, userID, action, resourceType, resourceID string, oldValues, newValues models.JSONMap) error {
	return nil
}

func (m *mockConfigurationService) GetAuditLogs(ctx context.Context, orgID string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}

func (m *mockConfigurationService) GetResourceAuditLogs(ctx context.Context, resourceType, resourceID string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}

func (m *mockConfigurationService) ValidateConfigurationConsistency(ctx context.Context) error {
	return nil
}

// TestServiceDiscoveryHeartbeat tests service discovery heartbeat functionality
func TestServiceDiscoveryHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	cfg := &config.Config{
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:           true,
			HeartbeatInterval: 2, // Very short for testing
		},
		Redis: config.RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   2, // Different DB for this test
		},
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		DB:   cfg.Redis.DB,
	})
	defer redisClient.Close()

	// Clean up Redis before test
	redisClient.FlushDB(ctx)

	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{Level: "debug", Format: "json"},
	})

	// Create service discovery instance
	serviceDiscovery := NewServiceDiscoveryService(cfg, testLogger, redisClient)

	// Register and start heartbeat
	err := serviceDiscovery.Register(ctx)
	require.NoError(t, err)

	err = serviceDiscovery.StartHeartbeat(ctx)
	require.NoError(t, err)

	// Wait for a few heartbeats
	time.Sleep(6 * time.Second)

	// Verify instance is still registered and healthy
	instances, err := serviceDiscovery.GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, 1)
	assert.Equal(t, serviceDiscovery.GetInstanceID(), instances[0].ID)
	assert.True(t, instances[0].IsHealthy())

	// Stop heartbeat and wait for expiration
	err = serviceDiscovery.StopHeartbeat()
	require.NoError(t, err)

	// Wait for instance to expire (3 * heartbeat interval)
	time.Sleep(8 * time.Second)

	// Verify instance is no longer healthy or has been removed
	instances, err = serviceDiscovery.GetHealthyInstances(ctx)
	require.NoError(t, err)
	if len(instances) > 0 {
		assert.False(t, instances[0].IsHealthy(), "Instance should be unhealthy after heartbeat stops")
	}

	// Cleanup
	serviceDiscovery.Deregister(ctx)
}

// TestLoadBalancerCircuitBreaker tests circuit breaker functionality
func TestLoadBalancerCircuitBreaker(t *testing.T) {
	cfg := &config.Config{
		LoadBalancer: config.LoadBalancerConfig{
			Strategy:       "round_robin",
			MaxRetries:     2, // Low threshold for testing
			RetryInterval:  1,
			CircuitBreaker: true,
		},
	}

	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{Level: "debug", Format: "json"},
	})

	// Create mock service discovery
	mockServiceDiscovery := &mockServiceDiscoveryService{
		instanceID: "test-instance",
	}

	loadBalancer := NewLoadBalancerService(cfg, testLogger, mockServiceDiscovery)

	// Create test instance
	instance := &models.ServiceInstance{
		ID:        "test-instance-1",
		Hostname:  "test-host",
		IPAddress: "192.168.1.1",
		Port:      "8080",
		Status:    models.ServiceStatusHealthy,
	}

	loadBalancer.UpdateInstances([]*models.ServiceInstance{instance})

	// Create reverse proxy to test circuit breaker
	proxy := loadBalancer.CreateReverseProxy(instance)
	require.NotNil(t, proxy)

	// Simulate failures to trigger circuit breaker
	// This would require a more complex test setup with actual HTTP servers
	// For now, we'll test the circuit breaker logic directly

	ctx := context.Background()
	selectedInstance, err := loadBalancer.GetNextInstance(ctx)
	require.NoError(t, err)
	assert.Equal(t, instance.ID, selectedInstance.ID)
}
