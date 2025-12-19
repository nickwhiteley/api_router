package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFieldMapping(t *testing.T) {
	validator := NewValidationService()

	t.Run("Valid field mapping", func(t *testing.T) {
		mapping := &FieldMapping{
			ConnectorID:       "connector-123",
			InboundFieldPath:  "request.user.name",
			OutboundFieldPath: "customer.fullName",
			IsActive:          true,
		}
		err := validator.ValidateStruct(mapping)
		assert.NoError(t, err)
	})

	t.Run("Valid field mapping with transform script", func(t *testing.T) {
		mapping := &FieldMapping{
			ConnectorID:       "connector-123",
			InboundFieldPath:  "request.user.firstName",
			OutboundFieldPath: "customer.name",
			TransformScript:   "value.upper()",
			IsActive:          true,
		}
		err := validator.ValidateStruct(mapping)
		assert.NoError(t, err)
	})

	t.Run("Invalid field mapping - missing connector ID", func(t *testing.T) {
		mapping := &FieldMapping{
			InboundFieldPath:  "request.user.name",
			OutboundFieldPath: "customer.fullName",
		}
		err := validator.ValidateStruct(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connector_id")
	})

	t.Run("Invalid field mapping - missing inbound field path", func(t *testing.T) {
		mapping := &FieldMapping{
			ConnectorID:       "connector-123",
			OutboundFieldPath: "customer.fullName",
		}
		err := validator.ValidateStruct(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "inbound_field_path")
	})

	t.Run("Invalid field mapping - missing outbound field path", func(t *testing.T) {
		mapping := &FieldMapping{
			ConnectorID:      "connector-123",
			InboundFieldPath: "request.user.name",
		}
		err := validator.ValidateStruct(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "outbound_field_path")
	})

	t.Run("Field mapping table name", func(t *testing.T) {
		mapping := FieldMapping{}
		assert.Equal(t, "field_mappings", mapping.TableName())
	})
}
