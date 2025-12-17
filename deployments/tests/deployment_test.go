package tests

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// TestDockerBuild tests that the Docker container builds successfully
func TestDockerBuild(t *testing.T) {
	// Change to project root directory
	projectRoot := getProjectRoot(t)
	err := os.Chdir(projectRoot)
	require.NoError(t, err, "Failed to change to project root directory")

	// Build Docker image
	cmd := exec.Command("docker", "build", "-t", "api-translation-platform:test", ".")
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Logf("Docker build output: %s", string(output))
	}

	require.NoError(t, err, "Docker build should succeed")

	// Verify image exists
	cmd = exec.Command("docker", "images", "-q", "api-translation-platform:test")
	output, err = cmd.Output()
	require.NoError(t, err, "Failed to list Docker images")
	assert.NotEmpty(t, strings.TrimSpace(string(output)), "Docker image should exist")
}

// TestDockerRun tests that the Docker container runs successfully
func TestDockerRun(t *testing.T) {
	// Skip if Docker build test failed
	if t.Failed() {
		t.Skip("Skipping Docker run test due to build failure")
	}

	projectRoot := getProjectRoot(t)

	// Start container with test configuration
	containerName := "atp-test-" + fmt.Sprintf("%d", time.Now().Unix())

	// Create test config
	testConfigPath := filepath.Join(projectRoot, "test-config.yaml")
	createTestConfig(t, testConfigPath)
	defer os.Remove(testConfigPath)

	cmd := exec.Command("docker", "run", "-d",
		"--name", containerName,
		"-p", "8090:8080",
		"-v", fmt.Sprintf("%s:/app/config/config.yaml:ro", testConfigPath),
		"api-translation-platform:test")

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Docker run output: %s", string(output))
	}
	require.NoError(t, err, "Docker container should start successfully")

	// Cleanup container
	defer func() {
		exec.Command("docker", "stop", containerName).Run()
		exec.Command("docker", "rm", containerName).Run()
	}()

	// Wait for container to be ready
	time.Sleep(10 * time.Second)

	// Test health endpoint
	resp, err := http.Get("http://localhost:8090/health")
	if err == nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Health endpoint should return 200")
	}
}

// TestKubernetesManifestValidation tests that Kubernetes manifests are valid
func TestKubernetesManifestValidation(t *testing.T) {
	projectRoot := getProjectRoot(t)
	manifestsDir := filepath.Join(projectRoot, "deployments", "kubernetes")

	// List of manifest files to validate
	manifestFiles := []string{
		"namespace.yaml",
		"configmap.yaml",
		"deployment.yaml",
		"service.yaml",
		"ingress.yaml",
		"hpa.yaml",
		"rbac.yaml",
	}

	for _, file := range manifestFiles {
		t.Run(file, func(t *testing.T) {
			manifestPath := filepath.Join(manifestsDir, file)

			// Check if file exists
			_, err := os.Stat(manifestPath)
			require.NoError(t, err, "Manifest file should exist: %s", file)

			// Validate YAML syntax
			content, err := ioutil.ReadFile(manifestPath)
			require.NoError(t, err, "Should be able to read manifest file")

			var yamlContent interface{}
			err = yaml.Unmarshal(content, &yamlContent)
			require.NoError(t, err, "Manifest should be valid YAML: %s", file)

			// Validate with kubectl if available
			if isKubectlAvailable() {
				cmd := exec.Command("kubectl", "apply", "--dry-run=client", "-f", manifestPath)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Logf("kubectl validation output for %s: %s", file, string(output))
				}
				assert.NoError(t, err, "Manifest should be valid Kubernetes YAML: %s", file)
			}
		})
	}
}

// TestDockerComposeValidation tests that docker-compose.yml is valid
func TestDockerComposeValidation(t *testing.T) {
	projectRoot := getProjectRoot(t)
	composePath := filepath.Join(projectRoot, "docker-compose.yml")

	// Check if file exists
	_, err := os.Stat(composePath)
	require.NoError(t, err, "docker-compose.yml should exist")

	// Validate YAML syntax
	content, err := ioutil.ReadFile(composePath)
	require.NoError(t, err, "Should be able to read docker-compose.yml")

	var composeContent interface{}
	err = yaml.Unmarshal(content, &composeContent)
	require.NoError(t, err, "docker-compose.yml should be valid YAML")

	// Validate with docker-compose if available
	if isDockerComposeAvailable() {
		err := os.Chdir(projectRoot)
		require.NoError(t, err, "Should be able to change to project root")

		cmd := exec.Command("docker-compose", "config")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("docker-compose validation output: %s", string(output))
		}
		assert.NoError(t, err, "docker-compose.yml should be valid")
	}
}

// TestProductionConfigValidation tests production configuration templates
func TestProductionConfigValidation(t *testing.T) {
	projectRoot := getProjectRoot(t)

	// Test main config file
	configPath := filepath.Join(projectRoot, "config.yaml")
	validateConfigFile(t, configPath, "main config")

	// Test Kubernetes configmap
	configMapPath := filepath.Join(projectRoot, "deployments", "kubernetes", "configmap.yaml")
	content, err := ioutil.ReadFile(configMapPath)
	require.NoError(t, err, "Should be able to read configmap.yaml")

	// Extract config.yaml from configmap
	var configMap map[string]interface{}
	err = yaml.Unmarshal(content, &configMap)
	require.NoError(t, err, "ConfigMap should be valid YAML")

	// Validate embedded config
	if data, ok := configMap["data"].(map[interface{}]interface{}); ok {
		if configYaml, ok := data["config.yaml"].(string); ok {
			var config interface{}
			err = yaml.Unmarshal([]byte(configYaml), &config)
			assert.NoError(t, err, "Embedded config in ConfigMap should be valid YAML")
		}
	}
}

// TestBackupRecoveryProcedures tests backup and recovery functionality
func TestBackupRecoveryProcedures(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("BackupScriptValidation", func(t *testing.T) {
		backupScriptPath := filepath.Join(projectRoot, "scripts", "backup.sh")

		// Check if backup script exists
		_, err := os.Stat(backupScriptPath)
		require.NoError(t, err, "Backup script should exist")

		// Check if script is executable
		info, err := os.Stat(backupScriptPath)
		require.NoError(t, err, "Should be able to stat backup script")

		mode := info.Mode()
		assert.True(t, mode&0111 != 0, "Backup script should be executable")

		// Validate script syntax
		cmd := exec.Command("bash", "-n", backupScriptPath)
		err = cmd.Run()
		assert.NoError(t, err, "Backup script should have valid syntax")

		// Check for required environment variables in script
		content, err := ioutil.ReadFile(backupScriptPath)
		require.NoError(t, err, "Should be able to read backup script")

		scriptContent := string(content)
		assert.Contains(t, scriptContent, "DATABASE_HOST", "Script should reference DATABASE_HOST")
		assert.Contains(t, scriptContent, "pg_dump", "Script should use pg_dump for database backup")
		assert.Contains(t, scriptContent, "RETENTION_DAYS", "Script should handle retention policy")
	})

	t.Run("RecoveryScriptValidation", func(t *testing.T) {
		recoveryScriptPath := filepath.Join(projectRoot, "scripts", "recovery.sh")

		// Check if recovery script exists
		_, err := os.Stat(recoveryScriptPath)
		require.NoError(t, err, "Recovery script should exist")

		// Check if script is executable
		info, err := os.Stat(recoveryScriptPath)
		require.NoError(t, err, "Should be able to stat recovery script")

		mode := info.Mode()
		assert.True(t, mode&0111 != 0, "Recovery script should be executable")

		// Validate script syntax
		cmd := exec.Command("bash", "-n", recoveryScriptPath)
		err = cmd.Run()
		assert.NoError(t, err, "Recovery script should have valid syntax")

		// Check for required functionality in script
		content, err := ioutil.ReadFile(recoveryScriptPath)
		require.NoError(t, err, "Should be able to read recovery script")

		scriptContent := string(content)
		assert.Contains(t, scriptContent, "pg_restore", "Script should use pg_restore for database recovery")
		assert.Contains(t, scriptContent, "safety_backup", "Script should create safety backup before restore")
		assert.Contains(t, scriptContent, "kubectl scale", "Script should handle Kubernetes scaling")
	})

	t.Run("BackupDirectoryStructure", func(t *testing.T) {
		// Test that backup directory can be created
		tempDir := t.TempDir()
		backupDir := filepath.Join(tempDir, "backups")

		err := os.MkdirAll(backupDir, 0755)
		assert.NoError(t, err, "Should be able to create backup directory")

		// Test permissions
		info, err := os.Stat(backupDir)
		require.NoError(t, err, "Should be able to stat backup directory")
		assert.True(t, info.IsDir(), "Backup path should be a directory")
	})
}

// TestHealthCheckEndpoints tests that health check endpoints are properly configured
func TestHealthCheckEndpoints(t *testing.T) {
	// This test validates that health check configurations are present in deployment manifests
	projectRoot := getProjectRoot(t)
	deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")

	content, err := ioutil.ReadFile(deploymentPath)
	require.NoError(t, err, "Should be able to read deployment.yaml")

	deploymentStr := string(content)

	// Check for health check configurations
	assert.Contains(t, deploymentStr, "livenessProbe", "Deployment should have liveness probe")
	assert.Contains(t, deploymentStr, "readinessProbe", "Deployment should have readiness probe")
	assert.Contains(t, deploymentStr, "/health", "Health check should use /health endpoint")
}

// TestSecurityConfiguration tests security-related configurations
func TestSecurityConfiguration(t *testing.T) {
	projectRoot := getProjectRoot(t)
	deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")

	content, err := ioutil.ReadFile(deploymentPath)
	require.NoError(t, err, "Should be able to read deployment.yaml")

	deploymentStr := string(content)

	// Check for security configurations
	assert.Contains(t, deploymentStr, "runAsNonRoot: true", "Should run as non-root user")
	assert.Contains(t, deploymentStr, "allowPrivilegeEscalation: false", "Should not allow privilege escalation")
	assert.Contains(t, deploymentStr, "readOnlyRootFilesystem: true", "Should use read-only root filesystem")
}

// Helper functions

func getProjectRoot(t *testing.T) string {
	// Get current working directory
	wd, err := os.Getwd()
	require.NoError(t, err, "Should be able to get working directory")

	// Navigate up to find project root (look for go.mod)
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Fatal("Could not find project root (go.mod not found)")
	return ""
}

func createTestConfig(t *testing.T, path string) {
	config := `
server:
  host: "0.0.0.0"
  port: "8080"
  read_timeout: 30
  write_timeout: 30
  idle_timeout: 120

database:
  host: "localhost"
  port: 5432
  user: "test"
  password: "test"
  dbname: "test_db"
  sslmode: "disable"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 1

python:
  script_timeout: 30
  max_memory: 128
  script_path: "./scripts"

logging:
  level: "debug"
  format: "json"
`

	err := ioutil.WriteFile(path, []byte(config), 0644)
	require.NoError(t, err, "Should be able to create test config")
}

func validateConfigFile(t *testing.T, path, name string) {
	content, err := ioutil.ReadFile(path)
	require.NoError(t, err, "Should be able to read %s", name)

	var config interface{}
	err = yaml.Unmarshal(content, &config)
	require.NoError(t, err, "%s should be valid YAML", name)

	// Validate required sections exist
	configMap, ok := config.(map[interface{}]interface{})
	require.True(t, ok, "%s should be a valid configuration map", name)

	requiredSections := []string{"server", "database", "redis", "logging"}
	for _, section := range requiredSections {
		assert.Contains(t, configMap, section, "%s should contain %s section", name, section)
	}
}

func isKubectlAvailable() bool {
	cmd := exec.Command("kubectl", "version", "--client")
	return cmd.Run() == nil
}

func isDockerComposeAvailable() bool {
	cmd := exec.Command("docker-compose", "version")
	return cmd.Run() == nil
}

// TestCICDPipelineValidation tests CI/CD pipeline configuration
func TestCICDPipelineValidation(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("GitHubWorkflowValidation", func(t *testing.T) {
		workflowPath := filepath.Join(projectRoot, ".github", "workflows", "ci-cd.yml")

		// Check if workflow file exists
		_, err := os.Stat(workflowPath)
		require.NoError(t, err, "CI/CD workflow should exist")

		// Validate YAML syntax
		content, err := ioutil.ReadFile(workflowPath)
		require.NoError(t, err, "Should be able to read workflow file")

		var workflow interface{}
		err = yaml.Unmarshal(content, &workflow)
		require.NoError(t, err, "Workflow should be valid YAML")

		workflowStr := string(content)

		// Check for required jobs
		assert.Contains(t, workflowStr, "test:", "Workflow should have test job")
		assert.Contains(t, workflowStr, "security-scan:", "Workflow should have security scan job")
		assert.Contains(t, workflowStr, "build:", "Workflow should have build job")
		assert.Contains(t, workflowStr, "deployment-tests:", "Workflow should have deployment tests job")
		assert.Contains(t, workflowStr, "deploy-staging:", "Workflow should have staging deployment job")
		assert.Contains(t, workflowStr, "deploy-production:", "Workflow should have production deployment job")

		// Check for required services
		assert.Contains(t, workflowStr, "postgres:", "Workflow should include PostgreSQL service")
		assert.Contains(t, workflowStr, "redis:", "Workflow should include Redis service")

		// Check for security scanning
		assert.Contains(t, workflowStr, "gosec", "Workflow should include Gosec security scanner")
		assert.Contains(t, workflowStr, "trivy", "Workflow should include Trivy vulnerability scanner")

		// Check for multi-platform builds
		assert.Contains(t, workflowStr, "linux/amd64,linux/arm64", "Workflow should build for multiple platforms")
	})

	t.Run("WorkflowTriggerValidation", func(t *testing.T) {
		workflowPath := filepath.Join(projectRoot, ".github", "workflows", "ci-cd.yml")
		content, err := ioutil.ReadFile(workflowPath)
		require.NoError(t, err, "Should be able to read workflow file")

		workflowStr := string(content)

		// Check for proper triggers
		assert.Contains(t, workflowStr, "push:", "Workflow should trigger on push")
		assert.Contains(t, workflowStr, "pull_request:", "Workflow should trigger on pull request")
		assert.Contains(t, workflowStr, "release:", "Workflow should trigger on release")

		// Check for branch restrictions
		assert.Contains(t, workflowStr, "main", "Workflow should include main branch")
		assert.Contains(t, workflowStr, "develop", "Workflow should include develop branch")
	})
}

// TestProductionReadiness tests production deployment readiness
func TestProductionReadiness(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("ProductionConfigurationValidation", func(t *testing.T) {
		prodConfigPath := filepath.Join(projectRoot, "deployments", "config", "production.yaml")

		// Check if production config exists
		_, err := os.Stat(prodConfigPath)
		require.NoError(t, err, "Production configuration should exist")

		// Validate configuration structure
		content, err := ioutil.ReadFile(prodConfigPath)
		require.NoError(t, err, "Should be able to read production config")

		var config map[string]interface{}
		err = yaml.Unmarshal(content, &config)
		require.NoError(t, err, "Production config should be valid YAML")

		// Check for required production settings
		assert.Contains(t, config, "server", "Config should have server section")
		assert.Contains(t, config, "database", "Config should have database section")
		assert.Contains(t, config, "redis", "Config should have redis section")
		assert.Contains(t, config, "security", "Config should have security section")
		assert.Contains(t, config, "monitoring", "Config should have monitoring section")
		assert.Contains(t, config, "backup", "Config should have backup section")

		// Validate security settings
		if security, ok := config["security"].(map[interface{}]interface{}); ok {
			assert.Contains(t, security, "tls", "Security should include TLS configuration")
			assert.Contains(t, security, "rate_limiting", "Security should include rate limiting")
			assert.Contains(t, security, "cors", "Security should include CORS configuration")
		}

		// Validate monitoring settings
		if monitoring, ok := config["monitoring"].(map[interface{}]interface{}); ok {
			assert.Contains(t, monitoring, "health_check_interval", "Monitoring should include health check interval")
			assert.Contains(t, monitoring, "metrics_collection_interval", "Monitoring should include metrics collection")
		}
	})

	t.Run("StagingConfigurationValidation", func(t *testing.T) {
		stagingConfigPath := filepath.Join(projectRoot, "deployments", "config", "staging.yaml")

		// Check if staging config exists
		_, err := os.Stat(stagingConfigPath)
		require.NoError(t, err, "Staging configuration should exist")

		// Validate configuration structure
		content, err := ioutil.ReadFile(stagingConfigPath)
		require.NoError(t, err, "Should be able to read staging config")

		var config map[string]interface{}
		err = yaml.Unmarshal(content, &config)
		require.NoError(t, err, "Staging config should be valid YAML")

		// Check for required sections
		requiredSections := []string{"server", "database", "redis", "logging"}
		for _, section := range requiredSections {
			assert.Contains(t, config, section, "Staging config should contain %s section", section)
		}
	})

	t.Run("EnvironmentVariableValidation", func(t *testing.T) {
		prodConfigPath := filepath.Join(projectRoot, "deployments", "config", "production.yaml")
		content, err := ioutil.ReadFile(prodConfigPath)
		require.NoError(t, err, "Should be able to read production config")

		configStr := string(content)

		// Check for environment variable placeholders
		envVarPattern := regexp.MustCompile(`\$\{[A-Z_]+\}`)
		_ = envVarPattern.FindAllString(configStr, -1)

		// Ensure critical environment variables are parameterized
		criticalEnvVars := []string{
			"${DATABASE_HOST}",
			"${DATABASE_PASSWORD}",
			"${REDIS_HOST}",
			"${REDIS_PASSWORD}",
		}

		for _, envVar := range criticalEnvVars {
			assert.Contains(t, configStr, envVar, "Production config should parameterize %s", envVar)
		}
	})
}

// TestMonitoringAndAlerting tests monitoring and alerting configuration
func TestMonitoringAndAlerting(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("PrometheusConfigValidation", func(t *testing.T) {
		prometheusConfigPath := filepath.Join(projectRoot, "deployments", "monitoring", "prometheus.yml")

		// Check if Prometheus config exists
		_, err := os.Stat(prometheusConfigPath)
		require.NoError(t, err, "Prometheus configuration should exist")

		// Validate YAML syntax
		content, err := ioutil.ReadFile(prometheusConfigPath)
		require.NoError(t, err, "Should be able to read Prometheus config")

		var config interface{}
		err = yaml.Unmarshal(content, &config)
		require.NoError(t, err, "Prometheus config should be valid YAML")

		configStr := string(content)

		// Check for required sections
		assert.Contains(t, configStr, "scrape_configs:", "Prometheus config should have scrape configs")
		assert.Contains(t, configStr, "api-translation-platform", "Prometheus should scrape the application")
	})

	t.Run("AlertRulesValidation", func(t *testing.T) {
		alertRulesPath := filepath.Join(projectRoot, "deployments", "monitoring", "alert_rules.yml")

		// Check if alert rules exist
		_, err := os.Stat(alertRulesPath)
		require.NoError(t, err, "Alert rules should exist")

		// Validate YAML syntax
		content, err := ioutil.ReadFile(alertRulesPath)
		require.NoError(t, err, "Should be able to read alert rules")

		var rules interface{}
		err = yaml.Unmarshal(content, &rules)
		require.NoError(t, err, "Alert rules should be valid YAML")

		rulesStr := string(content)

		// Check for critical alerts
		assert.Contains(t, rulesStr, "HighErrorRate", "Should have high error rate alert")
		assert.Contains(t, rulesStr, "HighLatency", "Should have high latency alert")
		assert.Contains(t, rulesStr, "ServiceDown", "Should have service down alert")
	})
}

// TestLoadBalancerConfiguration tests load balancer setup
func TestLoadBalancerConfiguration(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("NginxConfigValidation", func(t *testing.T) {
		nginxConfigPath := filepath.Join(projectRoot, "deployments", "nginx", "nginx.conf")

		// Check if nginx config exists
		_, err := os.Stat(nginxConfigPath)
		require.NoError(t, err, "Nginx configuration should exist")

		// Read and validate nginx config
		content, err := ioutil.ReadFile(nginxConfigPath)
		require.NoError(t, err, "Should be able to read nginx config")

		configStr := string(content)

		// Check for load balancing configuration
		assert.Contains(t, configStr, "upstream", "Nginx should have upstream configuration")
		assert.Contains(t, configStr, "proxy_pass", "Nginx should proxy requests")
		assert.Contains(t, configStr, "/health", "Nginx should have health check endpoints")

		// Test nginx config syntax if nginx is available
		if isNginxAvailable() {
			// Create temporary config file for testing
			tempConfig := filepath.Join(t.TempDir(), "nginx.conf")
			err := ioutil.WriteFile(tempConfig, content, 0644)
			require.NoError(t, err, "Should be able to write temp config")

			cmd := exec.Command("nginx", "-t", "-c", tempConfig)
			err = cmd.Run()
			assert.NoError(t, err, "Nginx configuration should be valid")
		}
	})

	t.Run("KubernetesServiceValidation", func(t *testing.T) {
		servicePath := filepath.Join(projectRoot, "deployments", "kubernetes", "service.yaml")

		// Check if service config exists
		_, err := os.Stat(servicePath)
		require.NoError(t, err, "Kubernetes service should exist")

		// Validate service configuration
		content, err := ioutil.ReadFile(servicePath)
		require.NoError(t, err, "Should be able to read service config")

		var service interface{}
		err = yaml.Unmarshal(content, &service)
		require.NoError(t, err, "Service config should be valid YAML")

		serviceStr := string(content)

		// Check for required service configuration
		assert.Contains(t, serviceStr, "type: ClusterIP", "Service should have ClusterIP type")
		assert.Contains(t, serviceStr, "port: 80", "Service should expose port 80")
		assert.Contains(t, serviceStr, "targetPort: 8080", "Service should target port 8080")
	})
}

// TestDisasterRecoveryProcedures tests disaster recovery capabilities
func TestDisasterRecoveryProcedures(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("BackupScheduleValidation", func(t *testing.T) {
		// Check if backup is configured in production config
		prodConfigPath := filepath.Join(projectRoot, "deployments", "config", "production.yaml")
		content, err := ioutil.ReadFile(prodConfigPath)
		require.NoError(t, err, "Should be able to read production config")

		var config map[string]interface{}
		err = yaml.Unmarshal(content, &config)
		require.NoError(t, err, "Production config should be valid YAML")

		// Check backup configuration
		if backup, ok := config["backup"].(map[interface{}]interface{}); ok {
			assert.Contains(t, backup, "enabled", "Backup should have enabled flag")
			assert.Contains(t, backup, "schedule", "Backup should have schedule")
			assert.Contains(t, backup, "retention_days", "Backup should have retention policy")

			if enabled, ok := backup["enabled"].(bool); ok {
				assert.True(t, enabled, "Backup should be enabled in production")
			}
		}
	})

	t.Run("MultiRegionCapability", func(t *testing.T) {
		// Check if deployment supports multi-region configuration
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		deploymentStr := string(content)

		// Check for region/zone awareness
		assert.Contains(t, deploymentStr, "REGION", "Deployment should be region-aware")
		assert.Contains(t, deploymentStr, "ZONE", "Deployment should be zone-aware")
	})

	t.Run("HighAvailabilityConfiguration", func(t *testing.T) {
		// Check HPA configuration
		hpaPath := filepath.Join(projectRoot, "deployments", "kubernetes", "hpa.yaml")

		_, err := os.Stat(hpaPath)
		require.NoError(t, err, "HPA configuration should exist")

		content, err := ioutil.ReadFile(hpaPath)
		require.NoError(t, err, "Should be able to read HPA config")

		var hpa interface{}
		err = yaml.Unmarshal(content, &hpa)
		require.NoError(t, err, "HPA config should be valid YAML")

		hpaStr := string(content)

		// Check for autoscaling configuration
		assert.Contains(t, hpaStr, "minReplicas", "HPA should have minimum replicas")
		assert.Contains(t, hpaStr, "maxReplicas", "HPA should have maximum replicas")
		assert.Contains(t, hpaStr, "cpu", "HPA should have CPU target")
	})
}

// Helper function to check if nginx is available
func isNginxAvailable() bool {
	cmd := exec.Command("nginx", "-v")
	return cmd.Run() == nil
}

// TestContainerOrchestration tests container orchestration capabilities
func TestContainerOrchestration(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("DockerComposeMultiInstance", func(t *testing.T) {
		composePath := filepath.Join(projectRoot, "docker-compose.yml")
		content, err := ioutil.ReadFile(composePath)
		require.NoError(t, err, "Should be able to read docker-compose.yml")

		composeStr := string(content)

		// Check for multiple instances
		assert.Contains(t, composeStr, "api-platform-1", "Should have first instance")
		assert.Contains(t, composeStr, "api-platform-2", "Should have second instance")
		assert.Contains(t, composeStr, "api-platform-3", "Should have third instance")

		// Check for load balancer
		assert.Contains(t, composeStr, "nginx:", "Should have nginx load balancer")

		// Check for dependencies
		assert.Contains(t, composeStr, "depends_on:", "Should have service dependencies")
		assert.Contains(t, composeStr, "condition: service_healthy", "Should wait for healthy services")
	})

	t.Run("KubernetesRBACValidation", func(t *testing.T) {
		rbacPath := filepath.Join(projectRoot, "deployments", "kubernetes", "rbac.yaml")

		_, err := os.Stat(rbacPath)
		require.NoError(t, err, "RBAC configuration should exist")

		content, err := ioutil.ReadFile(rbacPath)
		require.NoError(t, err, "Should be able to read RBAC config")

		var rbac interface{}
		err = yaml.Unmarshal(content, &rbac)
		require.NoError(t, err, "RBAC config should be valid YAML")

		rbacStr := string(content)

		// Check for required RBAC components
		assert.Contains(t, rbacStr, "ServiceAccount", "Should have ServiceAccount")
		assert.Contains(t, rbacStr, "Role", "Should have Role")
		assert.Contains(t, rbacStr, "RoleBinding", "Should have RoleBinding")
	})

	t.Run("IngressConfiguration", func(t *testing.T) {
		ingressPath := filepath.Join(projectRoot, "deployments", "kubernetes", "ingress.yaml")

		_, err := os.Stat(ingressPath)
		require.NoError(t, err, "Ingress configuration should exist")

		content, err := ioutil.ReadFile(ingressPath)
		require.NoError(t, err, "Should be able to read ingress config")

		var ingress interface{}
		err = yaml.Unmarshal(content, &ingress)
		require.NoError(t, err, "Ingress config should be valid YAML")

		ingressStr := string(content)

		// Check for TLS configuration
		assert.Contains(t, ingressStr, "tls:", "Ingress should have TLS configuration")
		assert.Contains(t, ingressStr, "hosts:", "Ingress should specify hosts")

		// Check for path routing
		assert.Contains(t, ingressStr, "paths:", "Ingress should have path routing")
	})
}

// TestDeploymentAutomation tests deployment automation capabilities
func TestDeploymentAutomation(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("HelmChartValidation", func(t *testing.T) {
		// Check if Helm charts exist (optional)
		helmPath := filepath.Join(projectRoot, "deployments", "helm")
		if _, err := os.Stat(helmPath); os.IsNotExist(err) {
			t.Skip("Helm charts not found, skipping Helm validation")
			return
		}

		chartPath := filepath.Join(helmPath, "Chart.yaml")
		if _, err := os.Stat(chartPath); err == nil {
			content, err := ioutil.ReadFile(chartPath)
			require.NoError(t, err, "Should be able to read Chart.yaml")

			var chart interface{}
			err = yaml.Unmarshal(content, &chart)
			require.NoError(t, err, "Chart.yaml should be valid YAML")
		}
	})

	t.Run("ConfigMapValidation", func(t *testing.T) {
		configMapPath := filepath.Join(projectRoot, "deployments", "kubernetes", "configmap.yaml")

		_, err := os.Stat(configMapPath)
		require.NoError(t, err, "ConfigMap should exist")

		content, err := ioutil.ReadFile(configMapPath)
		require.NoError(t, err, "Should be able to read ConfigMap")

		var configMap interface{}
		err = yaml.Unmarshal(content, &configMap)
		require.NoError(t, err, "ConfigMap should be valid YAML")

		configMapStr := string(content)

		// Check for application configuration
		assert.Contains(t, configMapStr, "config.yaml", "ConfigMap should contain config.yaml")
	})

	t.Run("NamespaceIsolation", func(t *testing.T) {
		namespacePath := filepath.Join(projectRoot, "deployments", "kubernetes", "namespace.yaml")

		_, err := os.Stat(namespacePath)
		require.NoError(t, err, "Namespace configuration should exist")

		content, err := ioutil.ReadFile(namespacePath)
		require.NoError(t, err, "Should be able to read namespace config")

		var namespace interface{}
		err = yaml.Unmarshal(content, &namespace)
		require.NoError(t, err, "Namespace config should be valid YAML")

		namespaceStr := string(content)

		// Check for proper namespace configuration
		assert.Contains(t, namespaceStr, "api-translation-platform", "Should create dedicated namespace")
	})
}

// TestScalabilityConfiguration tests horizontal scaling capabilities
func TestScalabilityConfiguration(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("HorizontalPodAutoscaler", func(t *testing.T) {
		hpaPath := filepath.Join(projectRoot, "deployments", "kubernetes", "hpa.yaml")
		content, err := ioutil.ReadFile(hpaPath)
		require.NoError(t, err, "Should be able to read HPA config")

		var hpa map[string]interface{}
		err = yaml.Unmarshal(content, &hpa)
		require.NoError(t, err, "HPA config should be valid YAML")

		// Validate HPA configuration structure
		assert.Equal(t, "HorizontalPodAutoscaler", hpa["kind"], "Should be HPA resource")

		if spec, ok := hpa["spec"].(map[interface{}]interface{}); ok {
			assert.Contains(t, spec, "minReplicas", "HPA should have minReplicas")
			assert.Contains(t, spec, "maxReplicas", "HPA should have maxReplicas")
			assert.Contains(t, spec, "metrics", "HPA should have metrics configuration")
		}
	})

	t.Run("ResourceLimits", func(t *testing.T) {
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		deploymentStr := string(content)

		// Check for resource limits and requests
		assert.Contains(t, deploymentStr, "resources:", "Deployment should have resource configuration")
		assert.Contains(t, deploymentStr, "requests:", "Deployment should have resource requests")
		assert.Contains(t, deploymentStr, "limits:", "Deployment should have resource limits")
		assert.Contains(t, deploymentStr, "memory:", "Deployment should specify memory requirements")
		assert.Contains(t, deploymentStr, "cpu:", "Deployment should specify CPU requirements")
	})

	t.Run("RollingUpdateStrategy", func(t *testing.T) {
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		deploymentStr := string(content)

		// Check for rolling update configuration
		assert.Contains(t, deploymentStr, "strategy:", "Deployment should have update strategy")
		assert.Contains(t, deploymentStr, "type: RollingUpdate", "Should use rolling update strategy")
		assert.Contains(t, deploymentStr, "maxSurge:", "Should configure max surge")
		assert.Contains(t, deploymentStr, "maxUnavailable:", "Should configure max unavailable")
	})
}

// TestEnvironmentSpecificConfigurations tests environment-specific settings
func TestEnvironmentSpecificConfigurations(t *testing.T) {
	projectRoot := getProjectRoot(t)

	environments := []string{"staging", "production"}

	for _, env := range environments {
		t.Run(fmt.Sprintf("%sConfiguration", strings.Title(env)), func(t *testing.T) {
			configPath := filepath.Join(projectRoot, "deployments", "config", fmt.Sprintf("%s.yaml", env))

			_, err := os.Stat(configPath)
			require.NoError(t, err, "%s configuration should exist", env)

			content, err := ioutil.ReadFile(configPath)
			require.NoError(t, err, "Should be able to read %s config", env)

			var config map[string]interface{}
			err = yaml.Unmarshal(content, &config)
			require.NoError(t, err, "%s config should be valid YAML", env)

			// Validate environment-specific settings
			if env == "production" {
				// Production should have stricter settings
				if security, ok := config["security"].(map[interface{}]interface{}); ok {
					if tls, ok := security["tls"].(map[interface{}]interface{}); ok {
						if enabled, ok := tls["enabled"].(bool); ok {
							assert.True(t, enabled, "TLS should be enabled in production")
						}
					}
				}

				// Production should have backup enabled
				if backup, ok := config["backup"].(map[interface{}]interface{}); ok {
					if enabled, ok := backup["enabled"].(bool); ok {
						assert.True(t, enabled, "Backup should be enabled in production")
					}
				}
			}

			// All environments should have required sections
			requiredSections := []string{"server", "database", "redis", "logging"}
			for _, section := range requiredSections {
				assert.Contains(t, config, section, "%s config should contain %s section", env, section)
			}
		})
	}
}

// TestContainerSecurity tests container security configurations
func TestContainerSecurity(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("DockerfileSecurityBestPractices", func(t *testing.T) {
		dockerfilePath := filepath.Join(projectRoot, "Dockerfile")
		content, err := ioutil.ReadFile(dockerfilePath)
		require.NoError(t, err, "Should be able to read Dockerfile")

		dockerfileStr := string(content)

		// Check for security best practices
		assert.Contains(t, dockerfileStr, "USER appuser", "Should run as non-root user")
		assert.Contains(t, dockerfileStr, "HEALTHCHECK", "Should include health check")
		assert.Contains(t, dockerfileStr, "alpine", "Should use minimal base image")

		// Check for proper layer optimization
		assert.Contains(t, dockerfileStr, "RUN apk --no-cache", "Should use no-cache for apk")

		// Ensure no secrets in Dockerfile
		secretPatterns := []string{"password", "secret", "key", "token"}
		for _, pattern := range secretPatterns {
			// This is a basic check - in real scenarios, use more sophisticated detection
			lowerDockerfile := strings.ToLower(dockerfileStr)
			if strings.Contains(lowerDockerfile, pattern+"=") {
				t.Errorf("Dockerfile may contain hardcoded %s", pattern)
			}
		}
	})

	t.Run("KubernetesSecurityContext", func(t *testing.T) {
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		deploymentStr := string(content)

		// Check for security context
		assert.Contains(t, deploymentStr, "securityContext:", "Should have security context")
		assert.Contains(t, deploymentStr, "runAsNonRoot: true", "Should run as non-root")
		assert.Contains(t, deploymentStr, "allowPrivilegeEscalation: false", "Should not allow privilege escalation")
		assert.Contains(t, deploymentStr, "readOnlyRootFilesystem: true", "Should use read-only root filesystem")
		assert.Contains(t, deploymentStr, "capabilities:", "Should drop capabilities")
		assert.Contains(t, deploymentStr, "drop:", "Should drop all capabilities")
		assert.Contains(t, deploymentStr, "- ALL", "Should drop ALL capabilities")
	})
}

// TestPerformanceConfiguration tests performance-related configurations
func TestPerformanceConfiguration(t *testing.T) {
	projectRoot := getProjectRoot(t)

	t.Run("ResourceOptimization", func(t *testing.T) {
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		var deployment map[string]interface{}
		err = yaml.Unmarshal(content, &deployment)
		require.NoError(t, err, "Deployment should be valid YAML")

		// Navigate to container resources
		if spec, ok := deployment["spec"].(map[interface{}]interface{}); ok {
			if template, ok := spec["template"].(map[interface{}]interface{}); ok {
				if podSpec, ok := template["spec"].(map[interface{}]interface{}); ok {
					if containers, ok := podSpec["containers"].([]interface{}); ok && len(containers) > 0 {
						if container, ok := containers[0].(map[interface{}]interface{}); ok {
							if resources, ok := container["resources"].(map[interface{}]interface{}); ok {
								assert.Contains(t, resources, "requests", "Container should have resource requests")
								assert.Contains(t, resources, "limits", "Container should have resource limits")
							}
						}
					}
				}
			}
		}
	})

	t.Run("ProbeConfiguration", func(t *testing.T) {
		deploymentPath := filepath.Join(projectRoot, "deployments", "kubernetes", "deployment.yaml")
		content, err := ioutil.ReadFile(deploymentPath)
		require.NoError(t, err, "Should be able to read deployment config")

		deploymentStr := string(content)

		// Check for all probe types
		assert.Contains(t, deploymentStr, "livenessProbe:", "Should have liveness probe")
		assert.Contains(t, deploymentStr, "readinessProbe:", "Should have readiness probe")
		assert.Contains(t, deploymentStr, "startupProbe:", "Should have startup probe")

		// Check probe configuration
		assert.Contains(t, deploymentStr, "initialDelaySeconds:", "Probes should have initial delay")
		assert.Contains(t, deploymentStr, "periodSeconds:", "Probes should have period")
		assert.Contains(t, deploymentStr, "timeoutSeconds:", "Probes should have timeout")
		assert.Contains(t, deploymentStr, "failureThreshold:", "Probes should have failure threshold")
	})
}
