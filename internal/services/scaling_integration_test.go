package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiInstanceConfigurationSync tests configuration synchronization across instances
func TestMultiInstanceConfigurationSync(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create test configuration
	cfg := &config.Config{
		ServiceDiscovery: config.ServiceDiscoveryConfig{
			Enabled:           true,
			HeartbeatInterval: 5,
			HealthCheckPath:   "/health",
		},
		Redis: config.RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   4, // Use different DB for testing
		},
	}

	// Create Redis client for testing
	redisClient := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		DB:   cfg.Redis.DB,
	})
	defer redisClient.Close()

	// Test Redis connection
	_, err := redisClient.Ping(ctx).Result()
	if err != nil {
		t.Skip("Redis not available, skipping integration test")
	}

	// Clean up Redis before test
	redisClient.FlushDB(ctx)

	// Create logger
	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "json",
		},
	})

	// Create multiple service discovery instances to simulate multiple instances
	const numInstances = 3
	var services []ServiceDiscoveryService

	// Create instances
	for i := 0; i < numInstances; i++ {
		serviceDiscovery := NewServiceDiscoveryService(cfg, testLogger, redisClient)
		services = append(services, serviceDiscovery)

		// Register each instance
		err := serviceDiscovery.Register(ctx)
		require.NoError(t, err)

		// Start heartbeat
		err = serviceDiscovery.StartHeartbeat(ctx)
		require.NoError(t, err)
	}

	// Wait for instances to register
	time.Sleep(2 * time.Second)

	// Verify all instances are registered
	instances, err := services[0].GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, numInstances)

	// Test that each instance has a unique ID
	instanceIDs := make(map[string]bool)
	for _, instance := range instances {
		assert.False(t, instanceIDs[instance.ID], "Instance ID should be unique")
		instanceIDs[instance.ID] = true
		assert.True(t, instance.IsHealthy())
	}

	// Cleanup
	for _, serviceDiscovery := range services {
		serviceDiscovery.StopHeartbeat()
		serviceDiscovery.Deregister(ctx)
	}

	// Wait for cleanup
	time.Sleep(1 * time.Second)

	// Verify instances are cleaned up
	instances, err = services[0].GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, 0)
}

// TestLoadDistributionFailover tests load distribution and failover scenarios
func TestLoadDistributionFailover(t *testing.T) {
	cfg := &config.Config{
		LoadBalancer: config.LoadBalancerConfig{
			Strategy:       "round_robin",
			MaxRetries:     3,
			RetryInterval:  2,
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

	ctx := context.Background()

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

// TestGracefulShutdownStartup tests graceful shutdown and startup procedures
func TestGracefulShutdownStartup(t *testing.T) {
	cfg := &config.Config{
		Clustering: config.ClusteringConfig{
			GracefulShutdownTimeout: 30,
		},
	}

	testLogger := logger.NewLogger(&config.Config{
		Logging: config.LoggingConfig{Level: "debug", Format: "json"},
	})

	// Create graceful shutdown service
	gracefulShutdown := NewGracefulShutdownService(cfg, testLogger)

	// Track hook execution
	var executedHooks []string

	// Register test hooks
	gracefulShutdown.RegisterStartupHook("test_startup_1", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "startup_1")
		return nil
	})

	gracefulShutdown.RegisterStartupHook("test_startup_2", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "startup_2")
		return nil
	})

	gracefulShutdown.RegisterShutdownHook("test_shutdown_1", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "shutdown_1")
		return nil
	})

	gracefulShutdown.RegisterShutdownHook("test_shutdown_2", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "shutdown_2")
		return nil
	})

	ctx := context.Background()

	// Test startup
	err := gracefulShutdown.Start(ctx)
	require.NoError(t, err)

	// Wait a bit for startup hooks to execute
	time.Sleep(100 * time.Millisecond)

	// Verify startup hooks were executed
	startupHooksExecuted := 0
	for _, hook := range executedHooks {
		if hook == "startup_1" || hook == "startup_2" {
			startupHooksExecuted++
		}
	}
	assert.Equal(t, 2, startupHooksExecuted, "Both startup hooks should be executed")

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err = gracefulShutdown.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// Verify shutdown hooks were executed
	shutdownHooksExecuted := 0
	for _, hook := range executedHooks {
		if hook == "shutdown_1" || hook == "shutdown_2" {
			shutdownHooksExecuted++
		}
	}
	assert.Equal(t, 2, shutdownHooksExecuted, "Both shutdown hooks should be executed")

	// Verify shutdown completion
	select {
	case <-gracefulShutdown.WaitForShutdown():
		// Expected - shutdown completed
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not complete within timeout")
	}
}
