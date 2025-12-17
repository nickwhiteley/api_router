package main

import (
	"context"
	"fmt"
	"log"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/container"
	"api-translation-platform/internal/server"
	"api-translation-platform/internal/services"

	"go.uber.org/fx"
)

func main() {
	app := fx.New(
		container.Module,
		fx.Invoke(func(
			lc fx.Lifecycle,
			cfg *config.Config,
			srv *server.Server,
			serviceDiscovery services.ServiceDiscoveryService,
			distributedConfig services.DistributedConfigService,
			gracefulShutdown services.GracefulShutdownService,
		) {
			lc.Append(fx.Hook{
				OnStart: func(ctx context.Context) error {
					log.Printf("Starting API Translation Platform on port %s", cfg.Server.Port)

					// Register shutdown hooks
					gracefulShutdown.RegisterShutdownHook("service_discovery", services.CreateServiceDiscoveryShutdownHook(serviceDiscovery))
					gracefulShutdown.RegisterShutdownHook("distributed_config", services.CreateDistributedConfigShutdownHook(distributedConfig))
					gracefulShutdown.RegisterShutdownHook("server", func(ctx context.Context) error {
						return srv.Stop()
					})

					// Start graceful shutdown service
					if err := gracefulShutdown.Start(ctx); err != nil {
						return fmt.Errorf("failed to start graceful shutdown service: %w", err)
					}

					// Register with service discovery
					if cfg.ServiceDiscovery.Enabled {
						if err := serviceDiscovery.Register(ctx); err != nil {
							return fmt.Errorf("failed to register with service discovery: %w", err)
						}

						if err := serviceDiscovery.StartHeartbeat(ctx); err != nil {
							return fmt.Errorf("failed to start heartbeat: %w", err)
						}
					}

					// Start distributed configuration sync
					if cfg.Clustering.Enabled {
						if err := distributedConfig.StartConfigSync(ctx); err != nil {
							return fmt.Errorf("failed to start config sync: %w", err)
						}
					}

					// Start server in background
					go func() {
						if err := srv.Start(context.Background()); err != nil {
							log.Printf("Server error: %v", err)
						}
					}()

					return nil
				},
				OnStop: func(ctx context.Context) error {
					log.Println("Shutting down API Translation Platform")
					return gracefulShutdown.Shutdown(ctx)
				},
			})
		}),
	)

	app.Run()
}
