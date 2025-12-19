package services

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
	"api-translation-platform/internal/repositories"
)

// SchemaService implementation

type schemaService struct {
	logger     *logger.Logger
	schemaRepo repositories.APISchemaRepository
}

// NewSchemaService creates a new schema service
func NewSchemaService(
	logger *logger.Logger,
	schemaRepo repositories.APISchemaRepository,
) SchemaService {
	return &schemaService{
		logger:     logger,
		schemaRepo: schemaRepo,
	}
}

func (s *schemaService) CreateSchema(ctx context.Context, schema *models.APISchema) (*models.APISchema, error) {
	s.logger.WithField("api_config_id", schema.APIConfigurationID).Info("Creating API schema")

	createdSchema, err := s.schemaRepo.Create(ctx, schema)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create API schema")
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	s.logger.WithField("schema_id", createdSchema.ID).Info("API schema created successfully")
	return createdSchema, nil
}

func (s *schemaService) UpdateSchema(ctx context.Context, schema *models.APISchema) (*models.APISchema, error) {
	s.logger.WithField("schema_id", schema.ID).Info("Updating API schema")

	updatedSchema, err := s.schemaRepo.Update(ctx, schema)
	if err != nil {
		s.logger.WithError(err).Error("Failed to update API schema")
		return nil, fmt.Errorf("failed to update schema: %w", err)
	}

	s.logger.WithField("schema_id", updatedSchema.ID).Info("API schema updated successfully")
	return updatedSchema, nil
}

func (s *schemaService) GetSchemaByAPIID(ctx context.Context, apiConfigID string) (*models.APISchema, error) {
	s.logger.WithField("api_config_id", apiConfigID).Info("Getting API schema")

	schema, err := s.schemaRepo.GetByAPIConfigurationID(ctx, apiConfigID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get API schema")
		return nil, fmt.Errorf("failed to get schema: %w", err)
	}

	// schema can be nil if no schema exists - this is expected
	return schema, nil
}

func (s *schemaService) DeleteSchema(ctx context.Context, schemaID string) error {
	s.logger.WithField("schema_id", schemaID).Info("Deleting API schema")

	err := s.schemaRepo.Delete(ctx, schemaID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to delete API schema")
		return fmt.Errorf("failed to delete schema: %w", err)
	}

	s.logger.WithField("schema_id", schemaID).Info("API schema deleted successfully")
	return nil
}

func (s *schemaService) ParseJSONSchema(ctx context.Context, jsonSchema string) (models.SchemaFields, error) {
	s.logger.Info("Parsing JSON schema")

	var schema map[string]interface{}
	if err := json.Unmarshal([]byte(jsonSchema), &schema); err != nil {
		return nil, fmt.Errorf("invalid JSON schema: %w", err)
	}

	fields := models.SchemaFields{}

	// Parse properties from JSON Schema
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		fields = s.parseJSONSchemaProperties(properties, "", schema)
	}

	s.logger.WithField("field_count", len(fields)).Info("JSON schema parsed successfully")
	return fields, nil
}

func (s *schemaService) ParseSampleData(ctx context.Context, sampleData map[string]interface{}) (models.SchemaFields, error) {
	s.logger.Info("Parsing sample data to generate schema")

	fields := models.SchemaFields{}
	s.parseSampleDataRecursive(sampleData, "", &fields)

	s.logger.WithField("field_count", len(fields)).Info("Sample data parsed successfully")
	return fields, nil
}

func (s *schemaService) GenerateSchemaFromSample(ctx context.Context, apiConfigID string, sampleData map[string]interface{}) (*models.APISchema, error) {
	s.logger.WithField("api_config_id", apiConfigID).Info("Generating schema from sample data")

	// Parse sample data to extract fields
	fields, err := s.ParseSampleData(ctx, sampleData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sample data: %w", err)
	}

	// Create schema
	schema := &models.APISchema{
		APIConfigurationID: apiConfigID,
		SchemaType:         "custom",
		SchemaContent: models.SchemaContent{
			SampleData:  sampleData,
			Description: "Auto-generated from sample data",
		},
		ParsedFields: fields,
	}

	return s.CreateSchema(ctx, schema)
}

// parseJSONSchemaProperties recursively parses JSON Schema properties
func (s *schemaService) parseJSONSchemaProperties(properties map[string]interface{}, prefix string, rootSchema map[string]interface{}) models.SchemaFields {
	fields := models.SchemaFields{}

	// Get required fields
	requiredFields := make(map[string]bool)
	if required, ok := rootSchema["required"].([]interface{}); ok {
		for _, field := range required {
			if fieldName, ok := field.(string); ok {
				requiredFields[fieldName] = true
			}
		}
	}

	for fieldName, fieldDef := range properties {
		fieldPath := fieldName
		if prefix != "" {
			fieldPath = prefix + "." + fieldName
		}

		if fieldDefMap, ok := fieldDef.(map[string]interface{}); ok {
			field := models.SchemaField{
				Path:     fieldPath,
				Required: requiredFields[fieldName],
			}

			// Extract type
			if fieldType, ok := fieldDefMap["type"].(string); ok {
				field.Type = fieldType
			}

			// Extract description
			if description, ok := fieldDefMap["description"].(string); ok {
				field.Description = description
			}

			// Extract format
			if format, ok := fieldDefMap["format"].(string); ok {
				field.Format = format
			}

			// Extract example
			if example, ok := fieldDefMap["example"]; ok {
				field.Example = example
			}

			// Extract enum
			if enum, ok := fieldDefMap["enum"].([]interface{}); ok {
				field.Enum = enum
			}

			fields = append(fields, field)

			// Handle nested objects
			if field.Type == "object" {
				if nestedProps, ok := fieldDefMap["properties"].(map[string]interface{}); ok {
					nestedFields := s.parseJSONSchemaProperties(nestedProps, fieldPath, fieldDefMap)
					fields = append(fields, nestedFields...)
				}
			}

			// Handle arrays
			if field.Type == "array" {
				if items, ok := fieldDefMap["items"].(map[string]interface{}); ok {
					if itemType, ok := items["type"].(string); ok && itemType == "object" {
						if itemProps, ok := items["properties"].(map[string]interface{}); ok {
							arrayFields := s.parseJSONSchemaProperties(itemProps, fieldPath+"[]", items)
							fields = append(fields, arrayFields...)
						}
					}
				}
			}
		}
	}

	return fields
}

// parseSampleDataRecursive recursively parses sample data to extract field information
func (s *schemaService) parseSampleDataRecursive(data interface{}, prefix string, fields *models.SchemaFields) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, value := range v {
			fieldPath := key
			if prefix != "" {
				fieldPath = prefix + "." + key
			}

			field := models.SchemaField{
				Path:     fieldPath,
				Type:     s.getTypeFromValue(value),
				Required: false, // Can't determine from sample data
				Example:  value,
			}

			*fields = append(*fields, field)

			// Recursively parse nested objects
			if field.Type == "object" {
				s.parseSampleDataRecursive(value, fieldPath, fields)
			}
		}
	case []interface{}:
		if len(v) > 0 {
			// Parse first element of array to understand structure
			arrayPath := prefix + "[]"
			s.parseSampleDataRecursive(v[0], arrayPath, fields)
		}
	}
}

// getTypeFromValue determines the JSON type from a Go value
func (s *schemaService) getTypeFromValue(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Bool:
		return "boolean"
	case reflect.Map:
		return "object"
	case reflect.Slice, reflect.Array:
		return "array"
	default:
		return "string"
	}
}
