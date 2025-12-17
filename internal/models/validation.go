package models

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// ValidationService provides model validation functionality
type ValidationService struct {
	validator *validator.Validate
}

// NewValidationService creates a new validation service
func NewValidationService() *ValidationService {
	v := validator.New()

	// Register custom tag name function to use json tags
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &ValidationService{validator: v}
}

// ValidateStruct validates a struct and returns detailed error information
func (vs *ValidationService) ValidateStruct(s interface{}) error {
	if err := vs.validator.Struct(s); err != nil {
		var validationErrors []string

		for _, err := range err.(validator.ValidationErrors) {
			validationErrors = append(validationErrors, fmt.Sprintf(
				"field '%s' failed validation: %s",
				err.Field(),
				vs.getErrorMessage(err),
			))
		}

		return fmt.Errorf("validation failed: %s", strings.Join(validationErrors, "; "))
	}

	return nil
}

// getErrorMessage returns a human-readable error message for validation errors
func (vs *ValidationService) getErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "this field is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return fmt.Sprintf("must be at least %s characters long", err.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters long", err.Param())
	case "oneof":
		return fmt.Sprintf("must be one of: %s", err.Param())
	case "url":
		return "must be a valid URL"
	default:
		return fmt.Sprintf("failed %s validation", err.Tag())
	}
}
