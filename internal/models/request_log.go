package models

import (
	"time"

	"gorm.io/gorm"
)

// RequestLog represents a logged API request
type RequestLog struct {
	ID             string         `json:"id" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	OrganisationID string         `json:"organisation_id" gorm:"type:uuid;not null;index" validate:"required"`
	ConnectorID    string         `json:"connector_id" gorm:"type:uuid;not null;index" validate:"required"`
	RequestID      string         `json:"request_id" gorm:"not null;index" validate:"required"`
	Method         string         `json:"method" gorm:"not null" validate:"required"`
	Path           string         `json:"path" gorm:"not null" validate:"required"`
	StatusCode     int            `json:"status_code" gorm:"not null"`
	ProcessingTime int64          `json:"processing_time"` // in milliseconds
	ErrorMessage   string         `json:"error_message,omitempty"`
	RequestBody    string         `json:"request_body,omitempty" gorm:"type:text"`
	ResponseBody   string         `json:"response_body,omitempty" gorm:"type:text"`
	Timestamp      time.Time      `json:"timestamp" gorm:"not null;index"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	// Relationships
	Organisation *Organisation `json:"organisation,omitempty" gorm:"foreignKey:OrganisationID"`
	Connector    *Connector    `json:"connector,omitempty" gorm:"foreignKey:ConnectorID"`
}

// TableName returns the table name for RequestLog
func (RequestLog) TableName() string {
	return "request_logs"
}

// IsError checks if the request resulted in an error
func (r *RequestLog) IsError() bool {
	return r.StatusCode >= 400 || r.ErrorMessage != ""
}

// IsSuccess checks if the request was successful
func (r *RequestLog) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 400 && r.ErrorMessage == ""
}
