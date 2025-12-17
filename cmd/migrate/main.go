package main

import (
	"fmt"
	"log"
	"os"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/database"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/migrate/main.go [up|down|status]")
		os.Exit(1)
	}

	command := os.Args[1]

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := database.NewConnection(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create migrator
	migrator := database.NewMigrator(db)

	switch command {
	case "up":
		fmt.Println("Running migrations...")
		if err := migrator.Up(); err != nil {
			log.Fatalf("Failed to run migrations: %v", err)
		}
		fmt.Println("Migrations completed successfully")

	case "down":
		fmt.Println("Rolling back migrations...")
		if err := migrator.Down(); err != nil {
			log.Fatalf("Failed to rollback migrations: %v", err)
		}
		fmt.Println("Migrations rolled back successfully")

	case "status":
		fmt.Println("Checking migration status...")
		// Get database connection stats
		stats, err := db.GetConnectionStats()
		if err != nil {
			log.Fatalf("Failed to get connection stats: %v", err)
		}

		fmt.Printf("Database connection status:\n")
		fmt.Printf("  Max Open Connections: %d\n", stats.MaxOpenConnections)
		fmt.Printf("  Open Connections: %d\n", stats.OpenConnections)
		fmt.Printf("  In Use: %d\n", stats.InUse)
		fmt.Printf("  Idle: %d\n", stats.Idle)

		// Check if tables exist
		sqlDB, err := db.DB.DB()
		if err != nil {
			log.Fatalf("Failed to get underlying sql.DB: %v", err)
		}

		var count int
		err = sqlDB.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'").Scan(&count)
		if err != nil {
			log.Fatalf("Failed to query table count: %v", err)
		}

		fmt.Printf("  Tables in database: %d\n", count)

		if count > 0 {
			fmt.Println("Database appears to be properly migrated")
		} else {
			fmt.Println("No tables found - migrations may need to be run")
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Available commands: up, down, status")
		os.Exit(1)
	}
}
