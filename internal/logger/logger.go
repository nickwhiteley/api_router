package logger

import (
	"api-translation-platform/internal/config"

	"github.com/sirupsen/logrus"
)

// Logger wraps logrus.Logger with additional functionality
type Logger struct {
	*logrus.Logger
}

// NewLogger creates a new structured logger instance
func NewLogger(cfg *config.Config) *Logger {
	log := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Set log format
	if cfg.Logging.Format == "json" {
		log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	return &Logger{Logger: log}
}

// WithOrganisation adds organisation context to log entries
func (l *Logger) WithOrganisation(orgID string) *logrus.Entry {
	return l.WithField("organisation_id", orgID)
}

// WithUser adds user context to log entries
func (l *Logger) WithUser(userID string) *logrus.Entry {
	return l.WithField("user_id", userID)
}

// WithRequest adds request context to log entries
func (l *Logger) WithRequest(requestID string) *logrus.Entry {
	return l.WithField("request_id", requestID)
}

// WithConnector adds connector context to log entries
func (l *Logger) WithConnector(connectorID string) *logrus.Entry {
	return l.WithField("connector_id", connectorID)
}
