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

// TestHorizontalScalingBasic tests basic horizontal scaling functionality
func TestHorizontalScalingBasic(t *testing.T) {
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
		LoadBalancer: config.LoadBalancerConfig{
			Strategy:       "round_robin",
			MaxRetries:     3,
			RetryInterval:  2,
			CircuitBreaker: true,
		},
		Clustering: config.ClusteringConfig{
			Enabled:                 true,
			ConfigSyncInterval:      10,
			LeaderElectionTimeout:   15,
			GracefulShutdownTimeout: 30,
		},
		Redis: config.RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   3, // Use different DB for testing
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

	t.Run("ServiceDiscoveryRegistration", func(t *testing.T) {
		testServiceDiscoveryRegistration(t, ctx, cfg, redisClient, testLogger)
	})

	t.Run("LoadBalancerRoundRobin", func(t *testing.T) {
		testLoadBalancerRoundRobin(t, ctx, cfg, testLogger)
	})

	t.Run("GracefulShutdownHooks", func(t *testing.T) {
		testGracefulShutdownHooks(t, ctx, cfg, testLogger)
	})
}

func testServiceDiscoveryRegistration(t *testing.T, ctx context.Context, cfg *config.Config, redisClient *redis.Client, testLogger *logger.Logger) {
	// Create service discovery instance
	serviceDiscovery := NewServiceDiscoveryService(cfg, testLogger, redisClient)

	// Register service
	err := serviceDiscovery.Register(ctx)
	require.NoError(t, err)

	// Verify registration
	instances, err := serviceDiscovery.GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, 1)
	assert.Equal(t, serviceDiscovery.GetInstanceID(), instances[0].ID)

	// Start heartbeat
	err = serviceDiscovery.StartHeartbeat(ctx)
	require.NoError(t, err)

	// Wait for heartbeat
	time.Sleep(2 * time.Second)

	// Verify instance is still healthy
	instances, err = serviceDiscovery.GetHealthyInstances(ctx)
	require.NoError(t, err)
	assert.Len(t, instances, 1)
	assert.True(t, instances[0].IsHealthy())

	// Cleanup
	serviceDiscovery.StopHeartbeat()
	serviceDiscovery.Deregister(ctx)
}

func testLoadBalancerRoundRobin(t *testing.T, ctx context.Context, cfg *config.Config, testLogger *logger.Logger) {
	// Create mock service discovery
	mockServiceDiscovery := &mockServiceDiscoveryService{
		instanceID: "test-instance",
	}

	// Create load balancer
	loadBalancer := NewLoadBalancerService(cfg, testLogger, mockServiceDiscovery)

	// Create test instances
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
	for i := 0; i < 15; i++ {
		instance, err := loadBalancer.GetNextInstance(ctx)
		require.NoError(t, err)
		require.NotNil(t, instance)
		selectedInstances[instance.ID]++
	}

	// Verify each instance was selected
	for _, instance := range instances {
		assert.True(t, selectedInstances[instance.ID] > 0,
			"Instance %s should be selected at least once", instance.ID)
	}

	// Verify healthy instance count
	assert.Equal(t, 3, loadBalancer.GetHealthyInstanceCount())
}

func testGracefulShutdownHooks(t *testing.T, ctx context.Context, cfg *config.Config, testLogger *logger.Logger) {
	// Create graceful shutdown service
	gracefulShutdown := NewGracefulShutdownService(cfg, testLogger)

	// Track hook execution
	var executedHooks []string

	// Register test hooks
	gracefulShutdown.RegisterStartupHook("test_startup", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "startup")
		return nil
	})

	gracefulShutdown.RegisterShutdownHook("test_shutdown", func(ctx context.Context) error {
		executedHooks = append(executedHooks, "shutdown")
		return nil
	})

	// Test startup
	err := gracefulShutdown.Start(ctx)
	require.NoError(t, err)

	// Wait for startup hooks to execute
	time.Sleep(100 * time.Millisecond)

	// Verify startup hook was executed
	assert.Contains(t, executedHooks, "startup")

	// Test graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err = gracefulShutdown.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// Verify shutdown hook was executed
	assert.Contains(t, executedHooks, "shutdown")

	// Verify shutdown completion
	select {
	case <-gracefulShutdown.WaitForShutdown():
		// Expected - shutdown completed
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not complete within timeout")
	}
}

// Mock service discovery for testing
type mockServiceDiscoveryService struct {
	instanceID string
}

func (m *mockServiceDiscoveryService) Register(ctx context.Context) error {
	return nil
}

func (m *mockServiceDiscoveryService) Deregister(ctx context.Context) error {
	return nil
}

func (m *mockServiceDiscoveryService) GetHealthyInstances(ctx context.Context) ([]*models.ServiceInstance, error) {
	return []*models.ServiceInstance{}, nil
}

func (m *mockServiceDiscoveryService) StartHeartbeat(ctx context.Context) error {
	return nil
}

func (m *mockServiceDiscoveryService) StopHeartbeat() error {
	return nil
}

func (m *mockServiceDiscoveryService) GetInstanceID() string {
	return m.instanceID
}
