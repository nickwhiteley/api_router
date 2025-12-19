package container

import (
	"api-translation-platform/internal/config"
	"api-translation-platform/internal/database"
	"api-translation-platform/internal/handlers"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/middleware"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
	"api-translation-platform/internal/security"
	"api-translation-platform/internal/server"
	"api-translation-platform/internal/services"
	"database/sql"

	"github.com/go-redis/redis/v8"
	"go.uber.org/fx"
	"gorm.io/gorm"
)

// Module provides dependency injection configuration
var Module = fx.Options(
	// Configuration
	fx.Provide(config.LoadConfig),

	// Logging
	fx.Provide(logger.NewLogger),

	// Database
	fx.Provide(database.NewConnection),
	fx.Provide(func(conn *database.Connection) *gorm.DB {
		return conn.DB
	}),
	fx.Provide(func(conn *database.Connection) (*sql.DB, error) {
		return conn.DB.DB()
	}),
	fx.Provide(database.NewMigrator),
	fx.Provide(database.NewRedisClient),

	// Repositories
	fx.Provide(repositories.NewOrganisationRepository),
	fx.Provide(repositories.NewUserRepository),
	fx.Provide(repositories.NewAPIConfigurationRepository),
	fx.Provide(repositories.NewConnectorRepository),
	fx.Provide(repositories.NewRequestLogRepository),
	fx.Provide(repositories.NewAuditLogRepository),
	fx.Provide(repositories.NewConfigurationVersionRepository),
	fx.Provide(repositories.NewMetricsRepository),
	fx.Provide(repositories.NewSecurityEventRepository),
	fx.Provide(func(ser *repositories.SecurityEventRepository) security.AuditRepository {
		return ser
	}),
	fx.Provide(repositories.NewHealthCheckRepository),
	fx.Provide(repositories.NewAlertRepository),
	fx.Provide(repositories.NewAPISchemaRepository),

	// Services
	fx.Provide(services.NewAPIGatewayService),
	fx.Provide(services.NewTransformationService),
	fx.Provide(services.NewOutboundClientService),
	fx.Provide(services.NewConfigurationService),
	fx.Provide(services.NewAuthenticationService),
	fx.Provide(services.NewAuthorizationService),
	fx.Provide(services.NewUserManagementService),
	fx.Provide(services.NewMonitoringService),
	fx.Provide(services.NewServiceDiscoveryService),
	fx.Provide(services.NewLoadBalancerService),
	fx.Provide(services.NewDistributedConfigService),
	fx.Provide(services.NewGracefulShutdownService),
	fx.Provide(services.NewCacheService),
	fx.Provide(services.NewPerformanceMonitor),
	fx.Provide(services.NewSchemaService),
	fx.Provide(func(redis *redis.Client, config *config.Config) *services.JobProcessor {
		return services.NewJobProcessor(redis, config, 5) // 5 workers by default
	}),

	// Handlers
	fx.Provide(handlers.NewLandingHandler),
	fx.Provide(handlers.NewAuthUIHandler),
	fx.Provide(handlers.NewConfigurationHandler),
	fx.Provide(handlers.NewManagementAPIHandler),
	fx.Provide(handlers.NewHealthHandler),
	fx.Provide(handlers.NewMetricsHandler),
	fx.Provide(handlers.NewWebUIHandler),
	fx.Provide(handlers.NewSecurityHandler),
	fx.Provide(handlers.NewPerformanceHandler),

	// Middleware
	fx.Provide(middleware.NewAuthenticationMiddleware),

	// Security
	fx.Provide(security.NewDatabaseAuditLogger),
	fx.Provide(func(dal *security.DatabaseAuditLogger) security.AuditLogger {
		return dal
	}),
	fx.Provide(security.NewSecurityManager),

	// Server
	fx.Provide(server.NewServer),

	// Models (for validation and serialization)
	fx.Provide(models.NewValidationService),

	// Invoke migrations on startup
	fx.Invoke(func(migrator *database.Migrator) error {
		return migrator.Up()
	}),
)
