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
	"strings"
	"sync"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
)

// ScriptExecutionError represents errors during script execution
type ScriptExecutionError struct {
	Message       string
	ScriptPath    string
	ExitCode      int
	Stderr        string
	DetailedError map[string]interface{} // Enhanced error details from Python
	InputData     string                 // Input data that caused the error
}

func (e *ScriptExecutionError) Error() string {
	var errorMsg strings.Builder
	errorMsg.WriteString(fmt.Sprintf("Python script execution failed: %s (exit code: %d)", e.Message, e.ExitCode))

	if e.Stderr != "" {
		errorMsg.WriteString(fmt.Sprintf("\nStderr: %s", e.Stderr))
	}

	if e.DetailedError != nil {
		if stackTrace, ok := e.DetailedError["stack_trace"].([]interface{}); ok && len(stackTrace) > 0 {
			errorMsg.WriteString("\nDetailed Stack Trace:")
			for i, frame := range stackTrace {
				if frameMap, ok := frame.(map[string]interface{}); ok {
					if lineContent, ok := frameMap["line_content"].(string); ok && lineContent != "" {
						errorMsg.WriteString(fmt.Sprintf("\n  Frame %d: %s", i+1, lineContent))
					}
				}
			}
		}
	}

	return errorMsg.String()
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

	// Execute the Python script directly to preserve detailed error information
	result, err := s.executePythonScript(ctx, scriptPath, inputJSON)
	if err != nil {
		// Don't use error handler here as it would wrap the ScriptExecutionError
		// and lose the detailed Python error information
		s.logger.WithError(err).
			WithField("script_path", scriptPath).
			Error("Python script execution failed")
		return nil, err
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
	// Properly escape the JSON data for Python
	escapedInputData := fmt.Sprintf("%q", string(inputData))

	wrapperScript := fmt.Sprintf(`
import sys
import json
import resource
import signal
import os
import traceback
import linecache

# Set memory limit (512MB) - increased to avoid memory issues
try:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
except (ValueError, OSError) as e:
    # If setting memory limit fails, continue without it
    pass

# Set timeout handler (using threading for better compatibility)
import threading
import time as time_module

def timeout_handler():
    time_module.sleep(60)  # 60 second timeout
    os._exit(124)  # Exit with timeout code

timeout_thread = threading.Thread(target=timeout_handler, daemon=True)
timeout_thread.start()

def get_detailed_error_info(exc_type, exc_value, exc_traceback):
    """Extract detailed error information including full stack trace"""
    error_info = {
        "error_type": exc_type.__name__,
        "error_message": str(exc_value),
        "full_traceback": traceback.format_exception(exc_type, exc_value, exc_traceback),
        "stack_trace": []
    }
    
    # Extract detailed stack trace information
    tb = exc_traceback
    while tb is not None:
        frame = tb.tb_frame
        filename = frame.f_code.co_filename
        line_number = tb.tb_lineno
        function_name = frame.f_code.co_name
        
        # Get the actual line of code that caused the error
        line_content = linecache.getline(filename, line_number).strip()
        
        # Get local variables at the time of error
        local_vars = {}
        try:
            for var_name, var_value in frame.f_locals.items():
                # Only include simple types to avoid serialization issues
                if isinstance(var_value, (str, int, float, bool, list, dict, type(None))):
                    try:
                        # Test if it's JSON serializable
                        json.dumps(var_value)
                        local_vars[var_name] = var_value
                    except (TypeError, ValueError):
                        local_vars[var_name] = str(var_value)[:100]  # Truncate long strings
                else:
                    local_vars[var_name] = f"<{type(var_value).__name__}>"
        except:
            local_vars = {"error": "Could not extract local variables"}
        
        error_info["stack_trace"].append({
            "filename": filename,
            "line_number": line_number,
            "function_name": function_name,
            "line_content": line_content,
            "local_variables": local_vars
        })
        
        tb = tb.tb_next
    
    return error_info

def detect_common_json_error(error_message, stack_trace):
    """Detect and provide helpful suggestions for common JSON errors"""
    if "the JSON object must be str, bytes or bytearray, not dict" in error_message:
        # Look for json.loads calls in the stack trace
        json_loads_calls = []
        for frame in stack_trace:
            if "json.loads" in frame.get("line_content", ""):
                json_loads_calls.append(frame)
        
        suggestion = """
🚨 COMMON ERROR DETECTED: You're trying to parse input_data with json.loads()

❌ PROBLEM: input_data is already a Python dictionary, not a JSON string.

✅ SOLUTION: Remove json.loads() and access fields directly:

WRONG:
    import json
    data = json.loads(input_data)  # ❌ This causes the error

CORRECT:
    # input_data is already a dict - use it directly
    user_name = input_data.get('name', 'Unknown')  # ✅ This works
    return {'greeting': f'Hello, {user_name}!'}

📖 The input_data parameter is already parsed for you. Just access its fields directly!
"""
        
        return {
            "common_error": "json_loads_on_dict",
            "suggestion": suggestion,
            "json_loads_calls": json_loads_calls
        }
    
    return None

try:
    # Provide input data - parse from JSON string
    input_data_json = %s
    input_data = json.loads(input_data_json)
    
    # Add helper functions and documentation for user scripts
    def json_loads_safe(data):
        """
        Helper function to safely parse JSON data.
        If data is already a dict/list, return it as-is.
        If data is a string, parse it as JSON.
        """
        if isinstance(data, (dict, list)):
            return data
        elif isinstance(data, str):
            return json.loads(data)
        else:
            raise TypeError(f"Cannot parse JSON from {type(data).__name__}")
    
    # Override json.loads to provide better error messages
    original_json_loads = json.loads
    def safer_json_loads(s, *args, **kwargs):
        if isinstance(s, dict):
            raise TypeError(
                "🚨 ERROR: You're trying to call json.loads() on input_data, but input_data is already a Python dictionary!\n\n"
                "❌ WRONG: json.loads(input_data)\n"
                "✅ CORRECT: input_data.get('field_name')\n\n"
                "The input_data parameter is already parsed for you. Access its fields directly!"
            )
        return original_json_loads(s, *args, **kwargs)
    
    # Replace json.loads with our safer version
    json.loads = safer_json_loads
    
    # Make helper available to user scripts
    locals()['json_loads_safe'] = json_loads_safe
    
    # Execute the user script
    exec(open('%s').read())
    
    # Expect the script to define a 'transform' function
    if 'transform' in locals():
        result = transform(input_data)
        print(json.dumps({"success": True, "result": result}))
    else:
        error_info = {
            "success": False,
            "error_type": "MissingFunction",
            "error_message": "Script must define a 'transform' function",
            "detailed_error": "The Python script must define a function named 'transform' that accepts input_data as a parameter and returns the transformed data. The input_data parameter is already a parsed Python dictionary - do not call json.loads() on it.",
            "suggestion": "Add a function like: def transform(input_data): return {'result': input_data['field_name']}"
        }
        print(json.dumps(error_info))
        
except Exception as e:
    exc_type, exc_value, exc_traceback = sys.exc_info()
    detailed_error = get_detailed_error_info(exc_type, exc_value, exc_traceback)
    
    # Check for common errors and provide helpful suggestions
    common_error_info = detect_common_json_error(str(e), detailed_error["stack_trace"])
    
    error_response = {
        "success": False,
        "error_type": detailed_error["error_type"],
        "error_message": detailed_error["error_message"],
        "detailed_error": detailed_error,
        "input_data_preview": str(input_data)[:200] if 'input_data' in locals() else "Could not parse input data"
    }
    
    # Add common error information if detected
    if common_error_info:
        error_response["common_error_detected"] = common_error_info
    
    print(json.dumps(error_response))
finally:
    pass  # Timeout thread will exit with the process
`, escapedInputData, scriptPath)

	wrapperPath, err := s.createTempScript(wrapperScript)
	if err != nil {
		return nil, fmt.Errorf("failed to create wrapper script: %w", err)
	}
	defer os.Remove(wrapperPath)

	// Execute with timeout
	ctx, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()

	// Try python3 first, then python as fallback
	pythonCmd := "python3"
	if _, err := exec.LookPath("python3"); err != nil {
		s.logger.Warn("python3 not found, trying python")
		pythonCmd = "python"
	}

	cmd := exec.CommandContext(ctx, pythonCmd, wrapperPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Check if the script file exists and is readable
	if _, err := os.Stat(wrapperPath); err != nil {
		s.logger.WithError(err).WithField("script_path", wrapperPath).Error("Script file not accessible")
		return nil, fmt.Errorf("script file not accessible: %w", err)
	}

	// Log the command execution start
	s.logger.WithField("script_path", wrapperPath).
		WithField("python_cmd", pythonCmd).
		WithField("timeout_seconds", 65).
		Info("Starting Python script execution")

	// Run the command
	startTime := time.Now()
	err = cmd.Run()
	executionTime := time.Since(startTime)

	// Log the execution result
	s.logger.WithField("execution_time_ms", executionTime.Milliseconds()).
		WithField("stdout_length", stdout.Len()).
		WithField("stderr_length", stderr.Len()).
		WithField("has_error", err != nil).
		Info("Python script execution completed")
	if err != nil {
		stderrStr := stderr.String()

		// Check for context timeout
		if ctx.Err() == context.DeadlineExceeded {
			s.logger.WithField("execution_time_ms", executionTime.Milliseconds()).
				WithField("stderr", stderrStr).
				Error("Python script execution timed out")
			return nil, fmt.Errorf("python script execution timed out after %v", executionTime)
		}

		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			// Create detailed error with stderr information
			detailedError := &ScriptExecutionError{
				Message:    fmt.Sprintf("Python script execution failed with exit code %d", exitError.ExitCode()),
				ScriptPath: scriptPath,
				ExitCode:   exitError.ExitCode(),
				Stderr:     stderrStr,
			}

			// Log the detailed stderr for debugging
			s.logger.WithField("stderr", stderrStr).
				WithField("exit_code", exitError.ExitCode()).
				WithField("execution_time_ms", executionTime.Milliseconds()).
				Error("Python script execution failed with stderr output")

			return nil, detailedError
		}

		// Log other types of errors
		s.logger.WithError(err).
			WithField("stderr", stderrStr).
			WithField("execution_time_ms", executionTime.Milliseconds()).
			Error("Python script execution failed with unknown error")

		return nil, fmt.Errorf("failed to execute script: %w", err)
	}

	output := stdout.Bytes()
	if len(output) == 0 {
		return nil, fmt.Errorf("script produced no output")
	}

	// Parse the enhanced output format
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		// If we can't parse the output, return it as-is with a warning
		s.logger.WithField("raw_output", string(output)).
			Warn("Could not parse script output as JSON, returning raw output")
		return output, nil
	}

	// Check if the script execution was successful
	if success, ok := result["success"].(bool); ok && !success {
		// Extract detailed error information
		errorType := "UnknownError"
		if et, ok := result["error_type"].(string); ok {
			errorType = et
		}

		errorMessage := "Unknown error occurred"
		if em, ok := result["error_message"].(string); ok {
			errorMessage = em
		}

		// Create a comprehensive error message with all available details
		var errorDetails strings.Builder
		errorDetails.WriteString(fmt.Sprintf("Python %s: %s", errorType, errorMessage))

		// Add detailed error information if available
		if detailedError, ok := result["detailed_error"].(map[string]interface{}); ok {
			if stackTrace, ok := detailedError["stack_trace"].([]interface{}); ok && len(stackTrace) > 0 {
				errorDetails.WriteString("\n\nStack Trace:")
				for i, frame := range stackTrace {
					if frameMap, ok := frame.(map[string]interface{}); ok {
						lineNum := "unknown"
						if ln, ok := frameMap["line_number"].(float64); ok {
							lineNum = fmt.Sprintf("%.0f", ln)
						}

						funcName := "unknown"
						if fn, ok := frameMap["function_name"].(string); ok {
							funcName = fn
						}

						lineContent := ""
						if lc, ok := frameMap["line_content"].(string); ok {
							lineContent = lc
						}

						errorDetails.WriteString(fmt.Sprintf("\n  Frame %d: %s() line %s", i+1, funcName, lineNum))
						if lineContent != "" {
							errorDetails.WriteString(fmt.Sprintf("\n    Code: %s", lineContent))
						}

						// Add local variables if available
						if localVars, ok := frameMap["local_variables"].(map[string]interface{}); ok && len(localVars) > 0 {
							errorDetails.WriteString("\n    Local variables:")
							for varName, varValue := range localVars {
								errorDetails.WriteString(fmt.Sprintf("\n      %s = %v", varName, varValue))
							}
						}
					}
				}
			}

			// Add full traceback if available
			if fullTraceback, ok := detailedError["full_traceback"].([]interface{}); ok && len(fullTraceback) > 0 {
				errorDetails.WriteString("\n\nFull Python Traceback:")
				for _, line := range fullTraceback {
					if lineStr, ok := line.(string); ok {
						errorDetails.WriteString("\n" + strings.TrimRight(lineStr, "\n"))
					}
				}
			}
		}

		// Add input data preview if available
		if inputPreview, ok := result["input_data_preview"].(string); ok {
			errorDetails.WriteString(fmt.Sprintf("\n\nInput Data Preview: %s", inputPreview))
		}

		// Add suggestion if available
		if suggestion, ok := result["suggestion"].(string); ok {
			errorDetails.WriteString(fmt.Sprintf("\n\nSuggestion: %s", suggestion))
		}

		// Create a ScriptExecutionError with detailed information
		scriptError := &ScriptExecutionError{
			Message:       fmt.Sprintf("Python %s: %s", errorType, errorMessage),
			ScriptPath:    scriptPath,
			ExitCode:      0,      // Script ran but returned error
			Stderr:        "",     // No stderr since script executed successfully but returned error
			DetailedError: result, // Store the complete error result from Python
		}

		// Add input data if available
		if inputPreview, ok := result["input_data_preview"].(string); ok {
			scriptError.InputData = inputPreview
		}

		return nil, scriptError
	}

	// Extract the actual result if execution was successful
	if actualResult, ok := result["result"]; ok {
		resultBytes, err := json.Marshal(actualResult)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal script result: %w", err)
		}
		return resultBytes, nil
	}

	// Fallback: return the original output
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
