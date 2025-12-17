package config

import (
	"github.com/spf13/viper"
)

// Config holds all configuration for the application
type Config struct {
	Server           ServerConfig           `mapstructure:"server"`
	Database         DatabaseConfig         `mapstructure:"database"`
	Redis            RedisConfig            `mapstructure:"redis"`
	Python           PythonConfig           `mapstructure:"python"`
	Logging          LoggingConfig          `mapstructure:"logging"`
	ServiceDiscovery ServiceDiscoveryConfig `mapstructure:"service_discovery"`
	LoadBalancer     LoadBalancerConfig     `mapstructure:"load_balancer"`
	Clustering       ClusteringConfig       `mapstructure:"clustering"`
	Performance      PerformanceConfig      `mapstructure:"performance"`
	Cache            CacheConfig            `mapstructure:"cache"`
	JobProcessor     JobProcessorConfig     `mapstructure:"job_processor"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port         string `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	IdleTimeout  int    `mapstructure:"idle_timeout"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// PythonConfig holds Python runtime configuration
type PythonConfig struct {
	ScriptTimeout int    `mapstructure:"script_timeout"`
	MaxMemory     int    `mapstructure:"max_memory"`
	ScriptPath    string `mapstructure:"script_path"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// ServiceDiscoveryConfig holds service discovery configuration
type ServiceDiscoveryConfig struct {
	Enabled           bool   `mapstructure:"enabled"`
	HeartbeatInterval int    `mapstructure:"heartbeat_interval"`
	HealthCheckPath   string `mapstructure:"health_check_path"`
}

// LoadBalancerConfig holds load balancer configuration
type LoadBalancerConfig struct {
	Strategy       string `mapstructure:"strategy"`
	HealthCheckURL string `mapstructure:"health_check_url"`
	MaxRetries     int    `mapstructure:"max_retries"`
	RetryInterval  int    `mapstructure:"retry_interval"`
	CircuitBreaker bool   `mapstructure:"circuit_breaker"`
}

// ClusteringConfig holds clustering configuration
type ClusteringConfig struct {
	Enabled                 bool   `mapstructure:"enabled"`
	NodeID                  string `mapstructure:"node_id"`
	ConfigSyncInterval      int    `mapstructure:"config_sync_interval"`
	LeaderElectionTimeout   int    `mapstructure:"leader_election_timeout"`
	GracefulShutdownTimeout int    `mapstructure:"graceful_shutdown_timeout"`
}

// PerformanceConfig holds performance monitoring configuration
type PerformanceConfig struct {
	Enabled                  bool `mapstructure:"enabled"`
	MetricCollectionInterval int  `mapstructure:"metric_collection_interval"`
	MetricRetentionDays      int  `mapstructure:"metric_retention_days"`
	EnableProfiling          bool `mapstructure:"enable_profiling"`
	ProfilingPort            int  `mapstructure:"profiling_port"`
}

// CacheConfig holds caching configuration
type CacheConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	DefaultTTL       int    `mapstructure:"default_ttl"`
	ConfigurationTTL int    `mapstructure:"configuration_ttl"`
	ConnectorTTL     int    `mapstructure:"connector_ttl"`
	UserTTL          int    `mapstructure:"user_ttl"`
	OrganisationTTL  int    `mapstructure:"organisation_ttl"`
	MetricsTTL       int    `mapstructure:"metrics_ttl"`
	MaxMemoryUsage   int    `mapstructure:"max_memory_usage"`
	EvictionPolicy   string `mapstructure:"eviction_policy"`
}

// JobProcessorConfig holds background job processing configuration
type JobProcessorConfig struct {
	Enabled    bool `mapstructure:"enabled"`
	Workers    int  `mapstructure:"workers"`
	QueueSize  int  `mapstructure:"queue_size"`
	MaxRetries int  `mapstructure:"max_retries"`
	JobTimeout int  `mapstructure:"job_timeout"`
}

// LoadConfig loads configuration from environment and config files
func LoadConfig() (*Config, error) {
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)
	viper.SetDefault("server.idle_timeout", 120)
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("python.script_timeout", 30)
	viper.SetDefault("python.max_memory", 128)
	viper.SetDefault("python.script_path", "./scripts")
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
	viper.SetDefault("service_discovery.enabled", true)
	viper.SetDefault("service_discovery.heartbeat_interval", 30)
	viper.SetDefault("service_discovery.health_check_path", "/health")
	viper.SetDefault("load_balancer.strategy", "round_robin")
	viper.SetDefault("load_balancer.health_check_url", "/health")
	viper.SetDefault("load_balancer.max_retries", 3)
	viper.SetDefault("load_balancer.retry_interval", 5)
	viper.SetDefault("load_balancer.circuit_breaker", true)
	viper.SetDefault("clustering.enabled", true)
	viper.SetDefault("clustering.config_sync_interval", 60)
	viper.SetDefault("clustering.leader_election_timeout", 30)
	viper.SetDefault("clustering.graceful_shutdown_timeout", 30)
	viper.SetDefault("performance.enabled", true)
	viper.SetDefault("performance.metric_collection_interval", 10)
	viper.SetDefault("performance.metric_retention_days", 7)
	viper.SetDefault("performance.enable_profiling", false)
	viper.SetDefault("performance.profiling_port", 6060)
	viper.SetDefault("cache.enabled", true)
	viper.SetDefault("cache.default_ttl", 300)
	viper.SetDefault("cache.configuration_ttl", 900)
	viper.SetDefault("cache.connector_ttl", 600)
	viper.SetDefault("cache.user_ttl", 1800)
	viper.SetDefault("cache.organisation_ttl", 3600)
	viper.SetDefault("cache.metrics_ttl", 300)
	viper.SetDefault("cache.max_memory_usage", 256)
	viper.SetDefault("cache.eviction_policy", "allkeys-lru")
	viper.SetDefault("job_processor.enabled", true)
	viper.SetDefault("job_processor.workers", 4)
	viper.SetDefault("job_processor.queue_size", 1000)
	viper.SetDefault("job_processor.max_retries", 3)
	viper.SetDefault("job_processor.job_timeout", 300)

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
