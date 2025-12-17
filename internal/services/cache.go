package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"api-translation-platform/internal/config"

	"github.com/go-redis/redis/v8"
)

// CacheService provides caching functionality using Redis
type CacheService struct {
	client *redis.Client
	config *config.Config
}

// NewCacheService creates a new cache service
func NewCacheService(client *redis.Client, config *config.Config) *CacheService {
	return &CacheService{
		client: client,
		config: config,
	}
}

// Get retrieves a value from cache
func (cs *CacheService) Get(ctx context.Context, key string, dest interface{}) error {
	val, err := cs.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return ErrCacheMiss
		}
		return fmt.Errorf("failed to get cache key %s: %w", key, err)
	}

	if err := json.Unmarshal([]byte(val), dest); err != nil {
		return fmt.Errorf("failed to unmarshal cached value for key %s: %w", key, err)
	}

	return nil
}

// Set stores a value in cache with expiration
func (cs *CacheService) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value for key %s: %w", key, err)
	}

	if err := cs.client.Set(ctx, key, data, expiration).Err(); err != nil {
		return fmt.Errorf("failed to set cache key %s: %w", key, err)
	}

	return nil
}

// Delete removes a key from cache
func (cs *CacheService) Delete(ctx context.Context, key string) error {
	if err := cs.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete cache key %s: %w", key, err)
	}
	return nil
}

// DeletePattern removes all keys matching a pattern
func (cs *CacheService) DeletePattern(ctx context.Context, pattern string) error {
	keys, err := cs.client.Keys(ctx, pattern).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys for pattern %s: %w", pattern, err)
	}

	if len(keys) > 0 {
		if err := cs.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys for pattern %s: %w", pattern, err)
		}
	}

	return nil
}

// Exists checks if a key exists in cache
func (cs *CacheService) Exists(ctx context.Context, key string) (bool, error) {
	count, err := cs.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check existence of key %s: %w", key, err)
	}
	return count > 0, nil
}

// SetWithTags stores a value with tags for cache invalidation
func (cs *CacheService) SetWithTags(ctx context.Context, key string, value interface{}, expiration time.Duration, tags []string) error {
	// Store the main value
	if err := cs.Set(ctx, key, value, expiration); err != nil {
		return err
	}

	// Store tag associations
	for _, tag := range tags {
		tagKey := fmt.Sprintf("tag:%s", tag)
		if err := cs.client.SAdd(ctx, tagKey, key).Err(); err != nil {
			return fmt.Errorf("failed to add key %s to tag %s: %w", key, tag, err)
		}
		// Set expiration for tag key (longer than the cached value)
		cs.client.Expire(ctx, tagKey, expiration+time.Hour)
	}

	return nil
}

// InvalidateByTag removes all cached values associated with a tag
func (cs *CacheService) InvalidateByTag(ctx context.Context, tag string) error {
	tagKey := fmt.Sprintf("tag:%s", tag)

	// Get all keys associated with this tag
	keys, err := cs.client.SMembers(ctx, tagKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get keys for tag %s: %w", tag, err)
	}

	// Delete all associated keys
	if len(keys) > 0 {
		if err := cs.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to delete keys for tag %s: %w", tag, err)
		}
	}

	// Delete the tag key itself
	if err := cs.client.Del(ctx, tagKey).Err(); err != nil {
		return fmt.Errorf("failed to delete tag key %s: %w", tagKey, err)
	}

	return nil
}

// GetStats returns cache statistics
func (cs *CacheService) GetStats(ctx context.Context) (*CacheStats, error) {
	info, err := cs.client.Info(ctx, "stats").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache stats: %w", err)
	}

	// Parse basic stats from Redis INFO command
	stats := &CacheStats{
		Info: info,
	}

	// Get memory usage
	memInfo, err := cs.client.Info(ctx, "memory").Result()
	if err == nil {
		stats.MemoryInfo = memInfo
	}

	return stats, nil
}

// CacheStats represents cache statistics
type CacheStats struct {
	Info       string `json:"info"`
	MemoryInfo string `json:"memory_info"`
}

// Cache key builders for different data types
func (cs *CacheService) BuildConfigurationKey(orgID uint, configID uint) string {
	return fmt.Sprintf("config:org:%d:config:%d", orgID, configID)
}

func (cs *CacheService) BuildConnectorKey(orgID uint, connectorID uint) string {
	return fmt.Sprintf("connector:org:%d:connector:%d", orgID, connectorID)
}

func (cs *CacheService) BuildUserKey(userID uint) string {
	return fmt.Sprintf("user:%d", userID)
}

func (cs *CacheService) BuildOrganisationKey(orgID uint) string {
	return fmt.Sprintf("org:%d", orgID)
}

func (cs *CacheService) BuildMetricsKey(orgID uint, timeframe string) string {
	return fmt.Sprintf("metrics:org:%d:timeframe:%s", orgID, timeframe)
}

// Cache invalidation tags
const (
	TagConfiguration = "configuration"
	TagConnector     = "connector"
	TagUser          = "user"
	TagOrganisation  = "organisation"
	TagMetrics       = "metrics"
)

// Common cache errors
var (
	ErrCacheMiss = fmt.Errorf("cache miss")
)

// CacheableRepository wraps a repository with caching functionality
type CacheableRepository struct {
	cache      *CacheService
	repository interface{}
}

// NewCacheableRepository creates a new cacheable repository wrapper
func NewCacheableRepository(cache *CacheService, repository interface{}) *CacheableRepository {
	return &CacheableRepository{
		cache:      cache,
		repository: repository,
	}
}

// CacheConfig holds caching configuration for different data types
type CacheConfig struct {
	ConfigurationTTL time.Duration
	ConnectorTTL     time.Duration
	UserTTL          time.Duration
	OrganisationTTL  time.Duration
	MetricsTTL       time.Duration
}

// DefaultCacheConfig returns default cache configuration
func DefaultCacheConfig() *CacheConfig {
	return &CacheConfig{
		ConfigurationTTL: 15 * time.Minute,
		ConnectorTTL:     10 * time.Minute,
		UserTTL:          30 * time.Minute,
		OrganisationTTL:  1 * time.Hour,
		MetricsTTL:       5 * time.Minute,
	}
}
