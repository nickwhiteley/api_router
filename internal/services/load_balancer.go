package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"api-translation-platform/internal/config"
	"api-translation-platform/internal/logger"
	"api-translation-platform/internal/models"
)

// LoadBalancerStrategy defines the load balancing strategy
type LoadBalancerStrategy string

const (
	RoundRobinStrategy         LoadBalancerStrategy = "round_robin"
	LeastConnectionsStrategy   LoadBalancerStrategy = "least_connections"
	WeightedRoundRobinStrategy LoadBalancerStrategy = "weighted_round_robin"
)

// LoadBalancerService handles load balancing across service instances
type LoadBalancerService interface {
	GetNextInstance(ctx context.Context) (*models.ServiceInstance, error)
	UpdateInstances(instances []*models.ServiceInstance)
	GetHealthyInstanceCount() int
	CreateReverseProxy(instance *models.ServiceInstance) *httputil.ReverseProxy
}

type loadBalancerService struct {
	config           *config.Config
	logger           *logger.Logger
	serviceDiscovery ServiceDiscoveryService
	strategy         LoadBalancerStrategy
	instances        []*models.ServiceInstance
	currentIndex     int64
	connectionCounts map[string]int64
	mu               sync.RWMutex
	circuitBreakers  map[string]*CircuitBreaker
}

// CircuitBreaker represents a circuit breaker for an instance
type CircuitBreaker struct {
	failures    int64
	lastFailure time.Time
	state       CircuitBreakerState
	mu          sync.RWMutex
}

type CircuitBreakerState string

const (
	CircuitBreakerClosed   CircuitBreakerState = "closed"
	CircuitBreakerOpen     CircuitBreakerState = "open"
	CircuitBreakerHalfOpen CircuitBreakerState = "half_open"
)

// NewLoadBalancerService creates a new load balancer service
func NewLoadBalancerService(
	config *config.Config,
	logger *logger.Logger,
	serviceDiscovery ServiceDiscoveryService,
) LoadBalancerService {
	strategy := LoadBalancerStrategy(config.LoadBalancer.Strategy)
	if strategy == "" {
		strategy = RoundRobinStrategy
	}

	return &loadBalancerService{
		config:           config,
		logger:           logger,
		serviceDiscovery: serviceDiscovery,
		strategy:         strategy,
		instances:        make([]*models.ServiceInstance, 0),
		connectionCounts: make(map[string]int64),
		circuitBreakers:  make(map[string]*CircuitBreaker),
	}
}

// GetNextInstance returns the next available service instance based on the load balancing strategy
func (lb *loadBalancerService) GetNextInstance(ctx context.Context) (*models.ServiceInstance, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.instances) == 0 {
		return nil, fmt.Errorf("no healthy instances available")
	}

	switch lb.strategy {
	case RoundRobinStrategy:
		return lb.roundRobinSelection(), nil
	case LeastConnectionsStrategy:
		return lb.leastConnectionsSelection(), nil
	case WeightedRoundRobinStrategy:
		return lb.weightedRoundRobinSelection(), nil
	default:
		return lb.roundRobinSelection(), nil
	}
}

// UpdateInstances updates the list of available instances
func (lb *loadBalancerService) UpdateInstances(instances []*models.ServiceInstance) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	// Filter out unhealthy instances and those with open circuit breakers
	healthyInstances := make([]*models.ServiceInstance, 0)
	for _, instance := range instances {
		if instance.IsHealthy() && !lb.isCircuitBreakerOpen(instance.ID) {
			healthyInstances = append(healthyInstances, instance)
		}
	}

	lb.instances = healthyInstances

	// Clean up connection counts for removed instances
	instanceIDs := make(map[string]bool)
	for _, instance := range healthyInstances {
		instanceIDs[instance.ID] = true
	}

	for id := range lb.connectionCounts {
		if !instanceIDs[id] {
			delete(lb.connectionCounts, id)
		}
	}

	lb.logger.WithField("healthy_instances", len(healthyInstances)).Debug("Updated load balancer instances")
}

// GetHealthyInstanceCount returns the number of healthy instances
func (lb *loadBalancerService) GetHealthyInstanceCount() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	return len(lb.instances)
}

// CreateReverseProxy creates a reverse proxy for the given instance
func (lb *loadBalancerService) CreateReverseProxy(instance *models.ServiceInstance) *httputil.ReverseProxy {
	target, _ := url.Parse(instance.GetEndpoint())

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the proxy to handle circuit breaker and connection counting
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Increment connection count
		lb.incrementConnectionCount(instance.ID)

		// Add instance metadata to headers
		req.Header.Set("X-Instance-ID", instance.ID)
		req.Header.Set("X-Instance-Host", instance.Hostname)
	}

	// Handle errors and circuit breaker logic
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		lb.logger.WithError(err).WithField("instance_id", instance.ID).Error("Proxy error")

		// Record failure for circuit breaker
		lb.recordFailure(instance.ID)

		// Decrement connection count
		lb.decrementConnectionCount(instance.ID)

		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Service temporarily unavailable"))
	}

	// Wrap the response to handle success cases
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Decrement connection count on successful response
		lb.decrementConnectionCount(instance.ID)

		// Record success for circuit breaker
		if resp.StatusCode < 500 {
			lb.recordSuccess(instance.ID)
		} else {
			lb.recordFailure(instance.ID)
		}

		return nil
	}

	return proxy
}

// roundRobinSelection implements round-robin load balancing
func (lb *loadBalancerService) roundRobinSelection() *models.ServiceInstance {
	if len(lb.instances) == 0 {
		return nil
	}

	index := atomic.AddInt64(&lb.currentIndex, 1) % int64(len(lb.instances))
	return lb.instances[index]
}

// leastConnectionsSelection implements least connections load balancing
func (lb *loadBalancerService) leastConnectionsSelection() *models.ServiceInstance {
	if len(lb.instances) == 0 {
		return nil
	}

	var selectedInstance *models.ServiceInstance
	minConnections := int64(-1)

	for _, instance := range lb.instances {
		connections := lb.connectionCounts[instance.ID]
		if minConnections == -1 || connections < minConnections {
			minConnections = connections
			selectedInstance = instance
		}
	}

	return selectedInstance
}

// weightedRoundRobinSelection implements weighted round-robin (simplified version)
func (lb *loadBalancerService) weightedRoundRobinSelection() *models.ServiceInstance {
	// For simplicity, this implementation treats all instances with equal weight
	// In a production system, you would implement proper weighted selection
	return lb.roundRobinSelection()
}

// incrementConnectionCount increments the connection count for an instance
func (lb *loadBalancerService) incrementConnectionCount(instanceID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.connectionCounts[instanceID]++
}

// decrementConnectionCount decrements the connection count for an instance
func (lb *loadBalancerService) decrementConnectionCount(instanceID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if lb.connectionCounts[instanceID] > 0 {
		lb.connectionCounts[instanceID]--
	}
}

// isCircuitBreakerOpen checks if the circuit breaker is open for an instance
func (lb *loadBalancerService) isCircuitBreakerOpen(instanceID string) bool {
	if !lb.config.LoadBalancer.CircuitBreaker {
		return false
	}

	cb, exists := lb.circuitBreakers[instanceID]
	if !exists {
		lb.circuitBreakers[instanceID] = &CircuitBreaker{
			state: CircuitBreakerClosed,
		}
		return false
	}

	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case CircuitBreakerOpen:
		// Check if we should transition to half-open
		if time.Since(cb.lastFailure) > time.Duration(lb.config.LoadBalancer.RetryInterval)*time.Second {
			cb.state = CircuitBreakerHalfOpen
			return false
		}
		return true
	case CircuitBreakerHalfOpen:
		return false
	default:
		return false
	}
}

// recordFailure records a failure for circuit breaker logic
func (lb *loadBalancerService) recordFailure(instanceID string) {
	if !lb.config.LoadBalancer.CircuitBreaker {
		return
	}

	cb, exists := lb.circuitBreakers[instanceID]
	if !exists {
		cb = &CircuitBreaker{state: CircuitBreakerClosed}
		lb.circuitBreakers[instanceID] = cb
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	// Open circuit breaker if failure threshold is reached
	if cb.failures >= int64(lb.config.LoadBalancer.MaxRetries) {
		cb.state = CircuitBreakerOpen
		lb.logger.WithField("instance_id", instanceID).Warn("Circuit breaker opened")
	}
}

// recordSuccess records a success for circuit breaker logic
func (lb *loadBalancerService) recordSuccess(instanceID string) {
	if !lb.config.LoadBalancer.CircuitBreaker {
		return
	}

	cb, exists := lb.circuitBreakers[instanceID]
	if !exists {
		return
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Reset failures and close circuit breaker
	cb.failures = 0
	if cb.state == CircuitBreakerHalfOpen {
		cb.state = CircuitBreakerClosed
		lb.logger.WithField("instance_id", instanceID).Info("Circuit breaker closed")
	}
}
