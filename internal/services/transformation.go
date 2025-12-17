package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
)

// ScriptExecutionError represents errors during script execution
type ScriptExecutionError struct {
	Message    string
	ScriptPath string
	ExitCode   int
	Stderr     string
}

func (e *ScriptExecutionError) Error() string {
	return fmt.Sprintf("script execution failed: %s (exit code: %d)", e.Message, e.ExitCode)
}

// ScriptCache holds cached scripts for hot-reload functionality
type ScriptCache struct {
	mu      sync.RWMutex
	scripts map[string]CachedScript
}

type CachedScript struct {
	Content   string
	Path      string
	UpdatedAt time.Time
}

// transformationService implements TransformationService
type transformationService struct {
	logger       *logger.Logger
	config       *config.Config
	scriptCache  *ScriptCache
	scriptsDir   string
	errorHandler *ErrorHandler
}

// NewTransformationService creates a new transformation service
func NewTransformationService(
	logger *logger.Logger,
	config *config.Config,
) TransformationService {
	scriptsDir := filepath.Join(".", "scripts")
	os.MkdirAll(scriptsDir, 0755)

	return &transformationService{
		logger: logger,
		config: config,
		scriptCache: &ScriptCache{
			scripts: make(map[string]CachedScript),
		},
		scriptsDir:   scriptsDir,
		errorHandler: NewErrorHandler(logger),
	}
}

// ExecuteScript executes a Python script with input data
func (s *transformationService) ExecuteScript(ctx context.Context, script string, inputData interface{}) (interface{}, error) {
	s.logger.Info("Executing Python script")

	// Create a temporary script file
	scriptPath, err := s.createTempScript(script)
	if err != nil {
		s.logger.WithError(err).Error("Failed to create temporary script file")
		return nil, fmt.Errorf("failed to create script file: %w", err)
	}
	defer os.Remove(scriptPath)

	// Prepare input data as JSON
	inputJSON, err := json.Marshal(inputData)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal input data")
		return nil, fmt.Errorf("failed to marshal input data: %w", err)
	}

	// Execute the Python script with comprehensive error handling
	var result []byte
	err = s.errorHandler.ExecuteWithFullProtection(ctx, func() error {
		var execErr error
		result, execErr = s.executePythonScript(ctx, scriptPath, inputJSON)
		return execErr
	}, "python_script_execution")

	if err != nil {
		return nil, s.errorHandler.HandleError(ctx, err, map[string]interface{}{
			"operation":   "script_execution",
			"script_path": scriptPath,
		})
	}

	// Parse the result
	var output interface{}
	if err := json.Unmarshal(result, &output); err != nil {
		s.logger.WithError(err).Error("Failed to parse script output")
		return nil, fmt.Errorf("failed to parse script output: %w", err)
	}

	s.logger.Info("Python script executed successfully")
	return output, nil
}

// ValidateScript validates Python script syntax
func (s *transformationService) ValidateScript(ctx context.Context, script string) error {
	s.logger.Info("Validating Python script")

	// Create a temporary script file
	scriptPath, err := s.createTempScript(script)
	if err != nil {
		return fmt.Errorf("failed to create script file: %w", err)
	}
	defer os.Remove(scriptPath)

	// Use Python's compile function to check syntax
	validateScript := fmt.Sprintf(`
import sys
import json

try:
    with open('%s', 'r') as f:
        code = f.read()
    compile(code, '%s', 'exec')
    print(json.dumps({"valid": True}))
except SyntaxError as e:
    print(json.dumps({"valid": False, "error": str(e)}))
except Exception as e:
    print(json.dumps({"valid": False, "error": str(e)}))
`, scriptPath, scriptPath)

	validatePath, err := s.createTempScript(validateScript)
	if err != nil {
		return fmt.Errorf("failed to create validation script: %w", err)
	}
	defer os.Remove(validatePath)

	// Execute validation with timeout
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python3", validatePath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("validation execution failed: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		return fmt.Errorf("failed to parse validation result: %w", err)
	}

	if valid, ok := result["valid"].(bool); !ok || !valid {
		errorMsg := "unknown syntax error"
		if errStr, ok := result["error"].(string); ok {
			errorMsg = errStr
		}
		return fmt.Errorf("script validation failed: %s", errorMsg)
	}

	s.logger.Info("Python script validation successful")
	return nil
}

// ReloadScript reloads a connector script
func (s *transformationService) ReloadScript(ctx context.Context, connectorID string) error {
	s.logger.WithConnector(connectorID).Info("Reloading script")

	s.scriptCache.mu.Lock()
	defer s.scriptCache.mu.Unlock()

	// Remove from cache to force reload on next execution
	delete(s.scriptCache.scripts, connectorID)

	s.logger.WithConnector(connectorID).Info("Script cache cleared for hot-reload")
	return nil
}

// createTempScript creates a temporary Python script file
func (s *transformationService) createTempScript(script string) (string, error) {
	// Create a temporary file in the scripts directory
	tempFile, err := os.CreateTemp(s.scriptsDir, "script_*.py")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	// Write the script content
	if _, err := tempFile.WriteString(script); err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to write script: %w", err)
	}

	return tempFile.Name(), nil
}

// executePythonScript executes a Python script with security constraints
func (s *transformationService) executePythonScript(ctx context.Context, scriptPath string, inputData []byte) ([]byte, error) {
	// Create a wrapper script that provides input data and captures output
	wrapperScript := fmt.Sprintf(`
import sys
import json
import resource
import signal
import os

# Set memory limit (128MB)
resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

# Set timeout handler
def timeout_handler(signum, frame):
    raise TimeoutError("Script execution timeout")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(30)  # 30 second timeout

try:
    # Provide input data
    input_data = %s
    
    # Execute the user script
    exec(open('%s').read())
    
    # Expect the script to define a 'transform' function
    if 'transform' in locals():
        result = transform(input_data)
        print(json.dumps(result))
    else:
        print(json.dumps({"error": "Script must define a 'transform' function"}))
        
except Exception as e:
    print(json.dumps({"error": str(e)}))
finally:
    signal.alarm(0)  # Cancel timeout
`, string(inputData), scriptPath)

	wrapperPath, err := s.createTempScript(wrapperScript)
	if err != nil {
		return nil, fmt.Errorf("failed to create wrapper script: %w", err)
	}
	defer os.Remove(wrapperPath)

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "python3", wrapperPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err = cmd.Run()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, &ScriptExecutionError{
				Message:    "Python script execution failed",
				ScriptPath: scriptPath,
				ExitCode:   exitError.ExitCode(),
				Stderr:     stderr.String(),
			}
		}
		return nil, fmt.Errorf("failed to execute script: %w", err)
	}

	output := stdout.Bytes()
	if len(output) == 0 {
		return nil, fmt.Errorf("script produced no output")
	}

	// Check if output contains an error
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err == nil {
		if errorMsg, ok := result["error"].(string); ok {
			return nil, fmt.Errorf("script error: %s", errorMsg)
		}
	}

	return output, nil
}

// GetCachedScript retrieves a script from cache or loads it
func (s *transformationService) GetCachedScript(connectorID string) (CachedScript, bool) {
	s.scriptCache.mu.RLock()
	defer s.scriptCache.mu.RUnlock()

	script, exists := s.scriptCache.scripts[connectorID]
	return script, exists
}

// CacheScript stores a script in the cache
func (s *transformationService) CacheScript(connectorID, content string) {
	s.scriptCache.mu.Lock()
	defer s.scriptCache.mu.Unlock()

	s.scriptCache.scripts[connectorID] = CachedScript{
		Content:   content,
		UpdatedAt: time.Now(),
	}
}
