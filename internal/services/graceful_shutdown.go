package services

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
)

// GracefulShutdownService handles graceful shutdown and startup procedures
type GracefulShutdownService interface {
	RegisterShutdownHook(name string, hook ShutdownHook)
	RegisterStartupHook(name string, hook StartupHook)
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	WaitForShutdown() <-chan struct{}
}

// ShutdownHook is a function called during graceful shutdown
type ShutdownHook func(ctx context.Context) error

// StartupHook is a function called during startup
type StartupHook func(ctx context.Context) error

type gracefulShutdownService struct {
	config         *config.Config
	logger         *logger.Logger
	shutdownHooks  map[string]ShutdownHook
	startupHooks   map[string]StartupHook
	shutdownChan   chan struct{}
	signalChan     chan os.Signal
	mu             sync.RWMutex
	isShuttingDown bool
}

// NewGracefulShutdownService creates a new graceful shutdown service
func NewGracefulShutdownService(
	config *config.Config,
	logger *logger.Logger,
) GracefulShutdownService {
	return &gracefulShutdownService{
		config:        config,
		logger:        logger,
		shutdownHooks: make(map[string]ShutdownHook),
		startupHooks:  make(map[string]StartupHook),
		shutdownChan:  make(chan struct{}),
		signalChan:    make(chan os.Signal, 1),
	}
}

// RegisterShutdownHook registers a shutdown hook
func (g *gracefulShutdownService) RegisterShutdownHook(name string, hook ShutdownHook) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.shutdownHooks[name] = hook
	g.logger.WithField("hook_name", name).Debug("Registered shutdown hook")
}

// RegisterStartupHook registers a startup hook
func (g *gracefulShutdownService) RegisterStartupHook(name string, hook StartupHook) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.startupHooks[name] = hook
	g.logger.WithField("hook_name", name).Debug("Registered startup hook")
}

// Start starts the graceful shutdown service and executes startup hooks
func (g *gracefulShutdownService) Start(ctx context.Context) error {
	g.logger.Info("Starting graceful shutdown service")

	// Execute startup hooks
	if err := g.executeStartupHooks(ctx); err != nil {
		return fmt.Errorf("startup hooks failed: %w", err)
	}

	// Set up signal handling
	signal.Notify(g.signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start signal handler goroutine
	go g.handleSignals(ctx)

	g.logger.Info("Graceful shutdown service started")
	return nil
}

// Shutdown initiates graceful shutdown
func (g *gracefulShutdownService) Shutdown(ctx context.Context) error {
	g.mu.Lock()
	if g.isShuttingDown {
		g.mu.Unlock()
		return fmt.Errorf("shutdown already in progress")
	}
	g.isShuttingDown = true
	g.mu.Unlock()

	g.logger.Info("Initiating graceful shutdown")

	// Create shutdown context with timeout
	timeout := time.Duration(g.config.Clustering.GracefulShutdownTimeout) * time.Second
	shutdownCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Execute shutdown hooks
	if err := g.executeShutdownHooks(shutdownCtx); err != nil {
		g.logger.WithError(err).Error("Some shutdown hooks failed")
	}

	// Signal shutdown completion
	close(g.shutdownChan)

	g.logger.Info("Graceful shutdown completed")
	return nil
}

// WaitForShutdown returns a channel that will be closed when shutdown is complete
func (g *gracefulShutdownService) WaitForShutdown() <-chan struct{} {
	return g.shutdownChan
}

// handleSignals handles OS signals for graceful shutdown
func (g *gracefulShutdownService) handleSignals(ctx context.Context) {
	for {
		select {
		case sig := <-g.signalChan:
			g.logger.WithField("signal", sig.String()).Info("Received shutdown signal")

			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				// Graceful shutdown
				if err := g.Shutdown(ctx); err != nil {
					g.logger.WithError(err).Error("Failed to shutdown gracefully")
					os.Exit(1)
				}
				return

			case syscall.SIGHUP:
				// Reload configuration (if implemented)
				g.logger.Info("Received SIGHUP - configuration reload not implemented")
			}

		case <-ctx.Done():
			return
		}
	}
}

// executeStartupHooks executes all registered startup hooks
func (g *gracefulShutdownService) executeStartupHooks(ctx context.Context) error {
	g.mu.RLock()
	hooks := make(map[string]StartupHook)
	for name, hook := range g.startupHooks {
		hooks[name] = hook
	}
	g.mu.RUnlock()

	g.logger.WithField("hook_count", len(hooks)).Info("Executing startup hooks")

	for name, hook := range hooks {
		g.logger.WithField("hook_name", name).Debug("Executing startup hook")

		if err := hook(ctx); err != nil {
			g.logger.WithError(err).WithField("hook_name", name).Error("Startup hook failed")
			return fmt.Errorf("startup hook '%s' failed: %w", name, err)
		}

		g.logger.WithField("hook_name", name).Debug("Startup hook completed")
	}

	g.logger.Info("All startup hooks completed successfully")
	return nil
}

// executeShutdownHooks executes all registered shutdown hooks
func (g *gracefulShutdownService) executeShutdownHooks(ctx context.Context) error {
	g.mu.RLock()
	hooks := make(map[string]ShutdownHook)
	for name, hook := range g.shutdownHooks {
		hooks[name] = hook
	}
	g.mu.RUnlock()

	g.logger.WithField("hook_count", len(hooks)).Info("Executing shutdown hooks")

	var errors []error

	// Execute hooks in parallel with timeout
	var wg sync.WaitGroup
	errorChan := make(chan error, len(hooks))

	for name, hook := range hooks {
		wg.Add(1)
		go func(hookName string, hookFunc ShutdownHook) {
			defer wg.Done()

			g.logger.WithField("hook_name", hookName).Debug("Executing shutdown hook")

			// Create individual timeout for each hook
			hookCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			if err := hookFunc(hookCtx); err != nil {
				g.logger.WithError(err).WithField("hook_name", hookName).Error("Shutdown hook failed")
				errorChan <- fmt.Errorf("shutdown hook '%s' failed: %w", hookName, err)
			} else {
				g.logger.WithField("hook_name", hookName).Debug("Shutdown hook completed")
			}
		}(name, hook)
	}

	// Wait for all hooks to complete
	go func() {
		wg.Wait()
		close(errorChan)
	}()

	// Collect errors
	for err := range errorChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		g.logger.WithField("error_count", len(errors)).Warn("Some shutdown hooks failed")
		return fmt.Errorf("shutdown hooks failed: %v", errors)
	}

	g.logger.Info("All shutdown hooks completed successfully")
	return nil
}

// Common shutdown hooks

// CreateDatabaseShutdownHook creates a shutdown hook for database connections
func CreateDatabaseShutdownHook(db interface{}) ShutdownHook {
	return func(ctx context.Context) error {
		// In a real implementation, this would close database connections
		// For now, we'll just log
		return nil
	}
}

// CreateRedisShutdownHook creates a shutdown hook for Redis connections
func CreateRedisShutdownHook(redis interface{}) ShutdownHook {
	return func(ctx context.Context) error {
		// In a real implementation, this would close Redis connections
		// For now, we'll just log
		return nil
	}
}

// CreateServiceDiscoveryShutdownHook creates a shutdown hook for service discovery
func CreateServiceDiscoveryShutdownHook(serviceDiscovery ServiceDiscoveryService) ShutdownHook {
	return func(ctx context.Context) error {
		if err := serviceDiscovery.StopHeartbeat(); err != nil {
			return fmt.Errorf("failed to stop heartbeat: %w", err)
		}

		if err := serviceDiscovery.Deregister(ctx); err != nil {
			return fmt.Errorf("failed to deregister service: %w", err)
		}

		return nil
	}
}

// CreateDistributedConfigShutdownHook creates a shutdown hook for distributed config
func CreateDistributedConfigShutdownHook(distributedConfig DistributedConfigService) ShutdownHook {
	return func(ctx context.Context) error {
		return distributedConfig.StopConfigSync()
	}
}
