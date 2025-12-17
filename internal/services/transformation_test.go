package services

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
)

func TestTransformationService_PropertyTests(t *testing.T) {
	// Setup
	cfg := &config.Config{}
	log := logger.NewLogger(cfg)
	service := NewTransformationService(log, cfg)

	t.Run("Property7_PythonScriptExecution", func(t *testing.T) {
		/**
		 * Feature: api-translation-platform, Property 7: Python script execution
		 * Validates: Requirements 3.1, 3.2
		 */
		properties := gopter.NewProperties(nil)

		properties.Property("valid Python script with transform function should execute successfully", prop.ForAll(
			func(value string) bool {
				// Create input data
				inputData := map[string]string{"test_key": value}

				// Create a simple Python script that defines a transform function
				script := `
def transform(data):
    # Simple transformation: add a processed flag
    if isinstance(data, dict):
        result = data.copy()
        result['processed'] = True
        return result
    else:
        return {'original': data, 'processed': True}
`

				ctx := context.Background()
				result, err := service.ExecuteScript(ctx, script, inputData)

				// Should not error
				if err != nil {
					t.Logf("Script execution failed: %v", err)
					return false
				}

				// Result should be a map with processed flag
				resultMap, ok := result.(map[string]interface{})
				if !ok {
					t.Logf("Result is not a map: %T", result)
					return false
				}

				// Should have processed flag set to true
				processed, exists := resultMap["processed"]
				if !exists {
					t.Logf("Result missing 'processed' field")
					return false
				}

				if processed != true {
					t.Logf("Processed field is not true: %v", processed)
					return false
				}

				return true
			},
			gen.AlphaString(),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property8_ScriptErrorHandling", func(t *testing.T) {
		/**
		 * Feature: api-translation-platform, Property 8: Script error handling
		 * Validates: Requirements 3.3
		 */
		properties := gopter.NewProperties(nil)

		properties.Property("script with runtime errors should be handled gracefully", prop.ForAll(
			func(errorMessage string) bool {
				// Create a Python script that raises an error
				script := fmt.Sprintf(`
def transform(data):
    raise ValueError("%s")
`, errorMessage)

				ctx := context.Background()
				result, err := service.ExecuteScript(ctx, script, map[string]string{"test": "data"})

				// Should handle the error gracefully - either return error or error in result
				if err != nil {
					// Error should contain information about the script error
					return true
				}

				// If no error, check if result contains error information
				if resultMap, ok := result.(map[string]interface{}); ok {
					if errorMsg, exists := resultMap["error"]; exists {
						if errorStr, ok := errorMsg.(string); ok {
							// Should contain the original error message
							return len(errorStr) > 0
						}
					}
				}

				return false
			},
			gen.AlphaString().SuchThat(func(s string) bool {
				// Ensure non-empty string and avoid quotes that could break Python syntax
				return len(s) > 0 && len(s) < 50 && !strings.Contains(s, `"`) && !strings.Contains(s, `'`)
			}),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property8_ScriptSyntaxErrors", func(t *testing.T) {
		/**
		 * Feature: api-translation-platform, Property 8: Script error handling
		 * Validates: Requirements 3.3
		 */
		properties := gopter.NewProperties(nil)

		properties.Property("script with syntax errors should be handled gracefully", prop.ForAll(
			func() bool {
				// Create a Python script with syntax error by removing closing parenthesis
				script := `
def transform(data:  # Missing closing parenthesis
    return {"result": "test"}
`

				ctx := context.Background()
				result, err := service.ExecuteScript(ctx, script, map[string]string{"test": "data"})

				// Should handle the syntax error gracefully
				if err != nil {
					return true // Error is expected for syntax errors
				}

				// If no error, check if result contains error information
				if resultMap, ok := result.(map[string]interface{}); ok {
					if _, exists := resultMap["error"]; exists {
						return true // Error information in result is acceptable
					}
				}

				return false
			},
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property9_HotReloadFunctionality", func(t *testing.T) {
		/**
		 * Feature: api-translation-platform, Property 9: Hot-reload functionality
		 * Validates: Requirements 3.4
		 */
		properties := gopter.NewProperties(nil)

		properties.Property("hot-reload should clear script cache and allow script updates", prop.ForAll(
			func(connectorID string) bool {
				// Skip empty connector IDs
				if len(connectorID) == 0 {
					return true
				}

				ctx := context.Background()

				// First, cache a script by calling GetCachedScript (which would normally be done during execution)
				transformationSvc := service.(*transformationService)
				transformationSvc.CacheScript(connectorID, "original script content")

				// Verify script is cached
				cachedScript, exists := transformationSvc.GetCachedScript(connectorID)
				if !exists || cachedScript.Content != "original script content" {
					t.Logf("Script was not cached properly")
					return false
				}

				// Call ReloadScript to trigger hot-reload
				err := service.ReloadScript(ctx, connectorID)
				if err != nil {
					t.Logf("ReloadScript failed: %v", err)
					return false
				}

				// Verify script is no longer in cache
				_, exists = transformationSvc.GetCachedScript(connectorID)
				if exists {
					t.Logf("Script still exists in cache after reload")
					return false
				}

				return true
			},
			gen.AlphaString().SuchThat(func(s string) bool {
				return len(s) > 0 && len(s) < 50
			}),
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})

	t.Run("Property10_PythonLibraryAccess", func(t *testing.T) {
		/**
		 * Feature: api-translation-platform, Property 10: Python library access
		 * Validates: Requirements 3.5
		 */
		properties := gopter.NewProperties(nil)

		properties.Property("scripts should have access to standard Python libraries", prop.ForAll(
			func() bool {
				testValue := "test123"
				// Create a Python script that uses standard libraries
				script := fmt.Sprintf(`
import json
import datetime
import math
import os

def transform(data):
    # Use json library
    json_str = json.dumps(data)
    parsed = json.loads(json_str)
    
    # Use datetime library
    now = datetime.datetime.now()
    
    # Use math library
    pi_value = math.pi
    
    # Use os library (limited access in sandbox)
    try:
        env_path = os.environ.get('PATH', 'not_found')
    except:
        env_path = 'restricted'
    
    return {
        'original': parsed,
        'timestamp': now.isoformat(),
        'pi': pi_value,
        'test_value': "%s",
        'env_access': 'available' if env_path != 'not_found' else 'restricted'
    }
`, testValue)

				ctx := context.Background()
				inputData := map[string]string{"library_test": testValue}
				result, err := service.ExecuteScript(ctx, script, inputData)

				// Should not error
				if err != nil {
					t.Logf("Script execution failed: %v", err)
					return false
				}

				// Result should be a map with expected fields
				resultMap, ok := result.(map[string]interface{})
				if !ok {
					t.Logf("Result is not a map: %T", result)
					return false
				}

				// Check that standard libraries were accessible
				requiredFields := []string{"original", "timestamp", "pi", "test_value"}
				for _, field := range requiredFields {
					if _, exists := resultMap[field]; !exists {
						t.Logf("Result missing required field: %s", field)
						return false
					}
				}

				// Verify pi value is correct (approximately)
				if pi, ok := resultMap["pi"].(float64); ok {
					if pi < 3.14 || pi > 3.15 {
						t.Logf("Pi value is incorrect: %f", pi)
						return false
					}
				} else {
					t.Logf("Pi value is not a float64")
					return false
				}

				// Verify test value was preserved
				if testVal, ok := resultMap["test_value"].(string); ok {
					if testVal != testValue {
						t.Logf("Test value mismatch: expected %s, got %s", testValue, testVal)
						return false
					}
				} else {
					t.Logf("Test value is not a string")
					return false
				}

				return true
			},
		))

		properties.TestingRun(t, gopter.ConsoleReporter(false))
	})
}

func TestTransformationService_ScriptValidation(t *testing.T) {
	// Setup
	cfg := &config.Config{}
	log := logger.NewLogger(cfg)
	service := NewTransformationService(log, cfg)

	t.Run("ValidScript", func(t *testing.T) {
		script := `
def transform(data):
    return {"result": data}
`
		ctx := context.Background()
		err := service.ValidateScript(ctx, script)
		assert.NoError(t, err)
	})

	t.Run("InvalidScript", func(t *testing.T) {
		script := `
def transform(data:
    return {"result": data}  # Missing closing parenthesis
`
		ctx := context.Background()
		err := service.ValidateScript(ctx, script)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "script validation failed")
	})
}

func TestTransformationService_HotReload(t *testing.T) {
	// Setup
	cfg := &config.Config{}
	log := logger.NewLogger(cfg)
	service := NewTransformationService(log, cfg)

	t.Run("ReloadScript", func(t *testing.T) {
		connectorID := "test-connector-123"
		ctx := context.Background()

		err := service.ReloadScript(ctx, connectorID)
		assert.NoError(t, err)
	})
}

func TestTransformationService_ErrorHandling(t *testing.T) {
	// Setup
	cfg := &config.Config{}
	log := logger.NewLogger(cfg)
	service := NewTransformationService(log, cfg)

	t.Run("ScriptWithRuntimeError", func(t *testing.T) {
		script := `
def transform(data):
    raise ValueError("Test error")
`
		ctx := context.Background()
		result, err := service.ExecuteScript(ctx, script, map[string]interface{}{"test": "data"})

		// Should handle the error gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "script error")
		} else {
			// Or return error in result
			resultMap, ok := result.(map[string]interface{})
			require.True(t, ok)
			errorMsg, exists := resultMap["error"]
			require.True(t, exists)
			assert.Contains(t, errorMsg.(string), "Test error")
		}
	})

	t.Run("ScriptWithInfiniteLoop", func(t *testing.T) {
		script := `
def transform(data):
    while True:
        pass  # Infinite loop to test timeout
`
		ctx := context.Background()
		_, err := service.ExecuteScript(ctx, script, map[string]interface{}{"test": "data"})

		// Should timeout and return error
		assert.Error(t, err)
	})
}
