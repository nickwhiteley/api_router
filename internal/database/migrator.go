package database

import (
	"api-translation-platform/internal/models"
)

// Migrator handles database migrations
type Migrator struct {
	db *Connection
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *Connection) *Migrator {
	return &Migrator{db: db}
}

// Up runs all pending migrations
func (m *Migrator) Up() error {
	return m.db.AutoMigrate(
		&models.Organisation{},
		&models.User{},
		&models.APIConfiguration{},
		&models.Connector{},
		&models.RequestLog{},
		&models.FieldMapping{},
		&models.APISchema{},
	)
}

// Down rolls back all migrations (for testing purposes)
func (m *Migrator) Down() error {
	return m.db.Migrator().DropTable(
		&models.APISchema{},
		&models.FieldMapping{},
		&models.RequestLog{},
		&models.Connector{},
		&models.APIConfiguration{},
		&models.User{},
		&models.Organisation{},
	)
}
