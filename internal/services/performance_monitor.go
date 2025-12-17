package services

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"api-translation-platform/internal/config"

	"github.com/go-redis/redis/v8"
)

// PerformanceMonitor tracks system performance metrics
type PerformanceMonitor struct {
	redis      *redis.Client
	config     *config.Config
	metrics    *sync.Map
	collectors []MetricCollector
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// MetricCollector defines the interface for metric collectors
type MetricCollector interface {
	Collect(ctx context.Context) (*PerformanceMetric, error)
	Name() string
}

// PerformanceMetric represents a performance metric
type PerformanceMetric struct {
	Name      string                 `json:"name"`
	Value     float64                `json:"value"`
	Unit      string                 `json:"unit"`
	Tags      map[string]string      `json:"tags"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// SystemMetrics represents system-wide performance metrics
type SystemMetrics struct {
	CPUUsage        float64          `json:"cpu_usage"`
	MemoryUsage     float64          `json:"memory_usage"`
	GoroutineCount  int              `json:"goroutine_count"`
	HeapSize        uint64           `json:"heap_size"`
	HeapInUse       uint64           `json:"heap_in_use"`
	GCPauses        []time.Duration  `json:"gc_pauses"`
	RequestMetrics  *RequestMetrics  `json:"request_metrics"`
	CacheMetrics    *CacheMetrics    `json:"cache_metrics"`
	DatabaseMetrics *DatabaseMetrics `json:"database_metrics"`
	Timestamp       time.Time        `json:"timestamp"`
}

// RequestMetrics tracks HTTP request performance
type RequestMetrics struct {
	TotalRequests     int64         `json:"total_requests"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	AverageLatency    time.Duration `json:"average_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	P99Latency        time.Duration `json:"p99_latency"`
	ErrorRate         float64       `json:"error_rate"`
	ActiveConnections int           `json:"active_connections"`
}

// CacheMetrics tracks cache performance
type CacheMetrics struct {
	HitRate     float64 `json:"hit_rate"`
	MissRate    float64 `json:"miss_rate"`
	TotalHits   int64   `json:"total_hits"`
	TotalMisses int64   `json:"total_misses"`
	Evictions   int64   `json:"evictions"`
	MemoryUsage uint64  `json:"memory_usage"`
}

// DatabaseMetrics tracks database performance
type DatabaseMetrics struct {
	ActiveConnections int           `json:"active_connections"`
	IdleConnections   int           `json:"idle_connections"`
	QueryLatency      time.Duration `json:"query_latency"`
	SlowQueries       int64         `json:"slow_queries"`
	ConnectionErrors  int64         `json:"connection_errors"`
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(redis *redis.Client, config *config.Config) *PerformanceMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	pm := &PerformanceMonitor{
		redis:   redis,
		config:  config,
		metrics: &sync.Map{},
		ctx:     ctx,
		cancel:  cancel,
	}

	// Register default collectors
	pm.collectors = []MetricCollector{
		&CPUCollector{},
		&MemoryCollector{},
		&GoroutineCollector{},
		&GCCollector{},
	}

	return pm
}

// Start begins performance monitoring
func (pm *PerformanceMonitor) Start() {
	pm.wg.Add(1)
	go pm.collectMetrics()

	pm.wg.Add(1)
	go pm.aggregateMetrics()
}

// Stop gracefully stops performance monitoring
func (pm *PerformanceMonitor) Stop() {
	pm.cancel()
	pm.wg.Wait()
}

// collectMetrics runs metric collection in a loop
func (pm *PerformanceMonitor) collectMetrics() {
	defer pm.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			for _, collector := range pm.collectors {
				metric, err := collector.Collect(pm.ctx)
				if err != nil {
					continue
				}

				pm.storeMetric(metric)
			}
		}
	}
}

// aggregateMetrics aggregates and stores metrics periodically
func (pm *PerformanceMonitor) aggregateMetrics() {
	defer pm.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			systemMetrics := pm.getSystemMetrics()
			pm.storeSystemMetrics(systemMetrics)
		}
	}
}

// storeMetric stores a single metric
func (pm *PerformanceMonitor) storeMetric(metric *PerformanceMetric) {
	key := fmt.Sprintf("metric:%s:%d", metric.Name, metric.Timestamp.Unix())

	// Store in Redis with expiration
	data := map[string]interface{}{
		"value":     metric.Value,
		"unit":      metric.Unit,
		"tags":      metric.Tags,
		"timestamp": metric.Timestamp.Unix(),
		"metadata":  metric.Metadata,
	}

	pm.redis.HMSet(pm.ctx, key, data)
	pm.redis.Expire(pm.ctx, key, 24*time.Hour)

	// Also store in memory for quick access
	pm.metrics.Store(metric.Name, metric)
}

// storeSystemMetrics stores aggregated system metrics
func (pm *PerformanceMonitor) storeSystemMetrics(metrics *SystemMetrics) {
	key := fmt.Sprintf("system_metrics:%d", metrics.Timestamp.Unix())

	// Store in Redis
	pm.redis.Set(pm.ctx, key, metrics, 24*time.Hour)

	// Store latest metrics
	pm.redis.Set(pm.ctx, "system_metrics:latest", metrics, 24*time.Hour)
}

// getSystemMetrics aggregates current system metrics
func (pm *PerformanceMonitor) getSystemMetrics() *SystemMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &SystemMetrics{
		CPUUsage:        pm.getCPUUsage(),
		MemoryUsage:     float64(m.Alloc) / float64(m.Sys) * 100,
		GoroutineCount:  runtime.NumGoroutine(),
		HeapSize:        m.HeapSys,
		HeapInUse:       m.HeapInuse,
		GCPauses:        pm.getGCPauses(&m),
		RequestMetrics:  pm.getRequestMetrics(),
		CacheMetrics:    pm.getCacheMetrics(),
		DatabaseMetrics: pm.getDatabaseMetrics(),
		Timestamp:       time.Now(),
	}
}

// GetCurrentMetrics returns current system metrics
func (pm *PerformanceMonitor) GetCurrentMetrics(ctx context.Context) (*SystemMetrics, error) {
	var metrics SystemMetrics
	err := pm.redis.Get(ctx, "system_metrics:latest").Scan(&metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to get current metrics: %w", err)
	}
	return &metrics, nil
}

// GetMetricHistory returns historical metrics for a specific metric
func (pm *PerformanceMonitor) GetMetricHistory(ctx context.Context, metricName string, duration time.Duration) ([]*PerformanceMetric, error) {
	pattern := fmt.Sprintf("metric:%s:*", metricName)
	keys, err := pm.redis.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get metric keys: %w", err)
	}

	var metrics []*PerformanceMetric
	cutoff := time.Now().Add(-duration)

	for _, key := range keys {
		data, err := pm.redis.HGetAll(ctx, key).Result()
		if err != nil {
			continue
		}

		timestamp := time.Unix(parseInt64(data["timestamp"]), 0)
		if timestamp.Before(cutoff) {
			continue
		}

		metric := &PerformanceMetric{
			Name:      metricName,
			Value:     parseFloat64(data["value"]),
			Unit:      data["unit"],
			Timestamp: timestamp,
		}

		metrics = append(metrics, metric)
	}

	return metrics, nil
}

// RecordRequestMetric records a request metric
func (pm *PerformanceMonitor) RecordRequestMetric(endpoint string, method string, statusCode int, duration time.Duration) {
	metric := &PerformanceMetric{
		Name:  "http_request",
		Value: float64(duration.Milliseconds()),
		Unit:  "ms",
		Tags: map[string]string{
			"endpoint":    endpoint,
			"method":      method,
			"status_code": fmt.Sprintf("%d", statusCode),
		},
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"duration_ns": duration.Nanoseconds(),
		},
	}

	pm.storeMetric(metric)
}

// RecordCacheMetric records a cache operation metric
func (pm *PerformanceMonitor) RecordCacheMetric(operation string, hit bool, duration time.Duration) {
	hitStr := "miss"
	if hit {
		hitStr = "hit"
	}

	metric := &PerformanceMetric{
		Name:  "cache_operation",
		Value: float64(duration.Microseconds()),
		Unit:  "μs",
		Tags: map[string]string{
			"operation": operation,
			"result":    hitStr,
		},
		Timestamp: time.Now(),
	}

	pm.storeMetric(metric)
}

// Helper methods and collectors

func (pm *PerformanceMonitor) getCPUUsage() float64 {
	// This is a simplified CPU usage calculation
	// In production, you'd want to use a proper CPU monitoring library
	return 0.0 // Placeholder
}

func (pm *PerformanceMonitor) getGCPauses(m *runtime.MemStats) []time.Duration {
	var pauses []time.Duration
	for i := 0; i < int(m.NumGC) && i < 10; i++ {
		pauses = append(pauses, time.Duration(m.PauseNs[i]))
	}
	return pauses
}

func (pm *PerformanceMonitor) getRequestMetrics() *RequestMetrics {
	// This would be populated from actual request tracking
	return &RequestMetrics{
		TotalRequests:     0,
		RequestsPerSecond: 0,
		AverageLatency:    0,
		P95Latency:        0,
		P99Latency:        0,
		ErrorRate:         0,
		ActiveConnections: 0,
	}
}

func (pm *PerformanceMonitor) getCacheMetrics() *CacheMetrics {
	// This would be populated from actual cache statistics
	return &CacheMetrics{
		HitRate:     0,
		MissRate:    0,
		TotalHits:   0,
		TotalMisses: 0,
		Evictions:   0,
		MemoryUsage: 0,
	}
}

func (pm *PerformanceMonitor) getDatabaseMetrics() *DatabaseMetrics {
	// This would be populated from actual database statistics
	return &DatabaseMetrics{
		ActiveConnections: 0,
		IdleConnections:   0,
		QueryLatency:      0,
		SlowQueries:       0,
		ConnectionErrors:  0,
	}
}

// Metric Collectors

// CPUCollector collects CPU metrics
type CPUCollector struct{}

func (c *CPUCollector) Name() string { return "cpu" }

func (c *CPUCollector) Collect(ctx context.Context) (*PerformanceMetric, error) {
	// Simplified CPU collection - in production use proper CPU monitoring
	return &PerformanceMetric{
		Name:      "cpu_usage",
		Value:     0.0, // Placeholder
		Unit:      "percent",
		Timestamp: time.Now(),
	}, nil
}

// MemoryCollector collects memory metrics
type MemoryCollector struct{}

func (c *MemoryCollector) Name() string { return "memory" }

func (c *MemoryCollector) Collect(ctx context.Context) (*PerformanceMetric, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &PerformanceMetric{
		Name:      "memory_usage",
		Value:     float64(m.Alloc),
		Unit:      "bytes",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"heap_size":    m.HeapSys,
			"heap_in_use":  m.HeapInuse,
			"stack_in_use": m.StackInuse,
		},
	}, nil
}

// GoroutineCollector collects goroutine metrics
type GoroutineCollector struct{}

func (c *GoroutineCollector) Name() string { return "goroutines" }

func (c *GoroutineCollector) Collect(ctx context.Context) (*PerformanceMetric, error) {
	return &PerformanceMetric{
		Name:      "goroutine_count",
		Value:     float64(runtime.NumGoroutine()),
		Unit:      "count",
		Timestamp: time.Now(),
	}, nil
}

// GCCollector collects garbage collection metrics
type GCCollector struct{}

func (c *GCCollector) Name() string { return "gc" }

func (c *GCCollector) Collect(ctx context.Context) (*PerformanceMetric, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &PerformanceMetric{
		Name:      "gc_cycles",
		Value:     float64(m.NumGC),
		Unit:      "count",
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"total_pause_ns": m.PauseTotalNs,
			"last_gc":        time.Unix(0, int64(m.LastGC)),
		},
	}, nil
}

// Utility functions
func parseInt64(s string) int64 {
	// Simplified parsing - in production use proper error handling
	return 0
}

func parseFloat64(s string) float64 {
	// Simplified parsing - in production use proper error handling
	return 0.0
}
