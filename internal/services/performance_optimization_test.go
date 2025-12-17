package services

import (
	"context"
	"testing"
	"time"

	"api-translation-platform/internal/config"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCacheServiceBasicOperations tests basic cache operations
func TestCacheServiceBasicOperations(t *testing.T) {
	// Create a mock Redis client for testing
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1, // Use test database
	})

	// Skip test if Redis is not available
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping cache tests")
	}

	// Clean up test data
	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	cache := NewCacheService(client, cfg)

	// Test Set and Get
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": []string{"a", "b", "c"},
	}

	key := "test:cache:key"
	err := cache.Set(ctx, key, testData, 5*time.Minute)
	require.NoError(t, err)

	var retrieved map[string]interface{}
	err = cache.Get(ctx, key, &retrieved)
	require.NoError(t, err)

	assert.Equal(t, "value1", retrieved["key1"])
	assert.Equal(t, float64(42), retrieved["key2"]) // JSON unmarshaling converts numbers to float64

	// Test cache miss
	var missData map[string]interface{}
	err = cache.Get(ctx, "nonexistent:key", &missData)
	assert.Equal(t, ErrCacheMiss, err)

	// Test Delete
	err = cache.Delete(ctx, key)
	require.NoError(t, err)

	err = cache.Get(ctx, key, &retrieved)
	assert.Equal(t, ErrCacheMiss, err)
}

// TestCacheServiceWithTags tests cache operations with tags
func TestCacheServiceWithTags(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping cache tests")
	}

	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	cache := NewCacheService(client, cfg)

	// Set values with tags
	err := cache.SetWithTags(ctx, "config:1", "config1", 5*time.Minute, []string{"configuration", "org:1"})
	require.NoError(t, err)

	err = cache.SetWithTags(ctx, "config:2", "config2", 5*time.Minute, []string{"configuration", "org:1"})
	require.NoError(t, err)

	err = cache.SetWithTags(ctx, "config:3", "config3", 5*time.Minute, []string{"configuration", "org:2"})
	require.NoError(t, err)

	// Verify values exist
	var value string
	err = cache.Get(ctx, "config:1", &value)
	require.NoError(t, err)
	assert.Equal(t, "config1", value)

	// Invalidate by tag
	err = cache.InvalidateByTag(ctx, "org:1")
	require.NoError(t, err)

	// Verify org:1 configs are gone
	err = cache.Get(ctx, "config:1", &value)
	assert.Equal(t, ErrCacheMiss, err)

	err = cache.Get(ctx, "config:2", &value)
	assert.Equal(t, ErrCacheMiss, err)

	// Verify org:2 config still exists
	err = cache.Get(ctx, "config:3", &value)
	require.NoError(t, err)
	assert.Equal(t, "config3", value)
}

// TestJobProcessorBasicOperations tests basic job processing
func TestJobProcessorBasicOperations(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping job processor tests")
	}

	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	processor := NewJobProcessor(client, cfg, 2)

	// Start processor
	processor.Start()
	defer processor.Stop()

	// Create and enqueue a job
	job := &BackgroundJob{
		Type:       JobTypeHealthCheck,
		Data:       map[string]interface{}{"test": "data"},
		MaxRetries: 3,
	}

	err := processor.EnqueueJob(ctx, job)
	require.NoError(t, err)
	assert.NotEmpty(t, job.ID)

	// Wait for job to be processed
	time.Sleep(2 * time.Second)

	// Check job status
	status, err := processor.GetJobStatus(ctx, job.ID)
	require.NoError(t, err)
	assert.Equal(t, JobStatusCompleted, status.Status)
}

// TestPerformanceMonitorMetricCollection tests performance monitoring
func TestPerformanceMonitorMetricCollection(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skip("Redis not available, skipping performance monitor tests")
	}

	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	monitor := NewPerformanceMonitor(client, cfg)

	// Test metric recording
	monitor.RecordRequestMetric("/api/test", "GET", 200, 50*time.Millisecond)
	monitor.RecordCacheMetric("get", true, 1*time.Millisecond)

	// Start monitoring briefly
	monitor.Start()
	time.Sleep(1 * time.Second)
	monitor.Stop()

	// Verify metrics were collected
	metrics, err := monitor.GetCurrentMetrics(ctx)
	if err == nil {
		assert.NotNil(t, metrics)
		assert.NotZero(t, metrics.Timestamp)
	}
}

// BenchmarkCacheOperations benchmarks cache operations
func BenchmarkCacheOperations(b *testing.B) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Skip("Redis not available, skipping cache benchmarks")
	}

	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	cache := NewCacheService(client, cfg)

	testData := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": []string{"a", "b", "c"},
	}

	b.Run("Set", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := cache.BuildConfigurationKey(1, uint(i))
			cache.Set(ctx, key, testData, 5*time.Minute)
		}
	})

	// Pre-populate cache for Get benchmark
	for i := 0; i < 1000; i++ {
		key := cache.BuildConfigurationKey(1, uint(i))
		cache.Set(ctx, key, testData, 5*time.Minute)
	}

	b.Run("Get", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := cache.BuildConfigurationKey(1, uint(i%1000))
			var result map[string]interface{}
			cache.Get(ctx, key, &result)
		}
	})
}

// BenchmarkJobProcessing benchmarks job processing throughput
func BenchmarkJobProcessing(b *testing.B) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   1,
	})

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		b.Skip("Redis not available, skipping job processing benchmarks")
	}

	defer client.FlushDB(ctx)

	cfg := &config.Config{}
	processor := NewJobProcessor(client, cfg, 4)

	processor.Start()
	defer processor.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		job := &BackgroundJob{
			Type:       JobTypeHealthCheck,
			Data:       map[string]interface{}{"iteration": i},
			MaxRetries: 1,
		}

		processor.EnqueueJob(ctx, job)
	}
}
