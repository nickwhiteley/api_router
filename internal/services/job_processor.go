package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"api-translation-platform/internal/config"

	"github.com/go-redis/redis/v8"
)

// JobProcessor handles background job processing
type JobProcessor struct {
	redis       *redis.Client
	config      *config.Config
	workers     int
	jobHandlers map[string]JobHandler
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// JobHandler defines the interface for job handlers
type JobHandler interface {
	Handle(ctx context.Context, job *BackgroundJob) error
}

// BackgroundJob represents a background job
type BackgroundJob struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Data        map[string]interface{} `json:"data"`
	Priority    int                    `json:"priority"`
	MaxRetries  int                    `json:"max_retries"`
	RetryCount  int                    `json:"retry_count"`
	CreatedAt   time.Time              `json:"created_at"`
	ScheduledAt time.Time              `json:"scheduled_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Status      JobStatus              `json:"status"`
}

// JobStatus represents the status of a background job
type JobStatus string

const (
	JobStatusPending   JobStatus = "pending"
	JobStatusRunning   JobStatus = "running"
	JobStatusCompleted JobStatus = "completed"
	JobStatusFailed    JobStatus = "failed"
	JobStatusRetrying  JobStatus = "retrying"
)

// Job types
const (
	JobTypeMetricsAggregation = "metrics_aggregation"
	JobTypeLogCleanup         = "log_cleanup"
	JobTypeConfigSync         = "config_sync"
	JobTypeHealthCheck        = "health_check"
	JobTypeDataExport         = "data_export"
)

// Redis keys for job queues
const (
	JobQueueKey      = "jobs:queue"
	JobProcessingKey = "jobs:processing"
	JobCompletedKey  = "jobs:completed"
	JobFailedKey     = "jobs:failed"
	JobScheduledKey  = "jobs:scheduled"
)

// NewJobProcessor creates a new job processor
func NewJobProcessor(redis *redis.Client, config *config.Config, workers int) *JobProcessor {
	ctx, cancel := context.WithCancel(context.Background())

	jp := &JobProcessor{
		redis:       redis,
		config:      config,
		workers:     workers,
		jobHandlers: make(map[string]JobHandler),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Register default job handlers
	jp.RegisterHandler(JobTypeMetricsAggregation, &MetricsAggregationHandler{})
	jp.RegisterHandler(JobTypeLogCleanup, &LogCleanupHandler{})
	jp.RegisterHandler(JobTypeConfigSync, &ConfigSyncHandler{})
	jp.RegisterHandler(JobTypeHealthCheck, &HealthCheckHandler{})
	jp.RegisterHandler(JobTypeDataExport, &DataExportHandler{})

	return jp
}

// RegisterHandler registers a job handler for a specific job type
func (jp *JobProcessor) RegisterHandler(jobType string, handler JobHandler) {
	jp.jobHandlers[jobType] = handler
}

// Start begins processing jobs
func (jp *JobProcessor) Start() {
	log.Printf("Starting job processor with %d workers", jp.workers)

	// Start worker goroutines
	for i := 0; i < jp.workers; i++ {
		jp.wg.Add(1)
		go jp.worker(i)
	}

	// Start scheduled job processor
	jp.wg.Add(1)
	go jp.scheduledJobProcessor()
}

// Stop gracefully stops the job processor
func (jp *JobProcessor) Stop() {
	log.Println("Stopping job processor...")
	jp.cancel()
	jp.wg.Wait()
	log.Println("Job processor stopped")
}

// EnqueueJob adds a job to the processing queue
func (jp *JobProcessor) EnqueueJob(ctx context.Context, job *BackgroundJob) error {
	job.CreatedAt = time.Now()
	job.Status = JobStatusPending

	if job.ID == "" {
		job.ID = fmt.Sprintf("%s_%d", job.Type, time.Now().UnixNano())
	}

	jobData, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("failed to marshal job: %w", err)
	}

	// Add to appropriate queue based on scheduling
	if job.ScheduledAt.IsZero() || job.ScheduledAt.Before(time.Now()) {
		// Add to immediate processing queue
		if err := jp.redis.LPush(ctx, JobQueueKey, jobData).Err(); err != nil {
			return fmt.Errorf("failed to enqueue job: %w", err)
		}
	} else {
		// Add to scheduled jobs with score as timestamp
		score := float64(job.ScheduledAt.Unix())
		if err := jp.redis.ZAdd(ctx, JobScheduledKey, &redis.Z{
			Score:  score,
			Member: jobData,
		}).Err(); err != nil {
			return fmt.Errorf("failed to schedule job: %w", err)
		}
	}

	return nil
}

// GetJobStatus retrieves the status of a job
func (jp *JobProcessor) GetJobStatus(ctx context.Context, jobID string) (*BackgroundJob, error) {
	// Check in processing queue
	if job := jp.findJobInList(ctx, JobProcessingKey, jobID); job != nil {
		return job, nil
	}

	// Check in completed queue
	if job := jp.findJobInList(ctx, JobCompletedKey, jobID); job != nil {
		return job, nil
	}

	// Check in failed queue
	if job := jp.findJobInList(ctx, JobFailedKey, jobID); job != nil {
		return job, nil
	}

	return nil, fmt.Errorf("job not found: %s", jobID)
}

// worker processes jobs from the queue
func (jp *JobProcessor) worker(workerID int) {
	defer jp.wg.Done()

	log.Printf("Worker %d started", workerID)

	for {
		select {
		case <-jp.ctx.Done():
			log.Printf("Worker %d stopping", workerID)
			return
		default:
			// Block and wait for a job
			result, err := jp.redis.BRPopLPush(jp.ctx, JobQueueKey, JobProcessingKey, time.Second).Result()
			if err != nil {
				if err == redis.Nil {
					continue // No jobs available, continue waiting
				}
				log.Printf("Worker %d error getting job: %v", workerID, err)
				continue
			}

			var job BackgroundJob
			if err := json.Unmarshal([]byte(result), &job); err != nil {
				log.Printf("Worker %d error unmarshaling job: %v", workerID, err)
				continue
			}

			jp.processJob(workerID, &job)
		}
	}
}

// processJob processes a single job
func (jp *JobProcessor) processJob(workerID int, job *BackgroundJob) {
	log.Printf("Worker %d processing job %s (type: %s)", workerID, job.ID, job.Type)

	job.Status = JobStatusRunning
	now := time.Now()
	job.StartedAt = &now

	// Update job status in processing queue
	jp.updateJobInProcessing(job)

	// Get handler for job type
	handler, exists := jp.jobHandlers[job.Type]
	if !exists {
		jp.failJob(job, fmt.Errorf("no handler registered for job type: %s", job.Type))
		return
	}

	// Execute job with timeout
	ctx, cancel := context.WithTimeout(jp.ctx, 5*time.Minute)
	defer cancel()

	err := handler.Handle(ctx, job)

	if err != nil {
		if job.RetryCount < job.MaxRetries {
			jp.retryJob(job, err)
		} else {
			jp.failJob(job, err)
		}
	} else {
		jp.completeJob(job)
	}
}

// completeJob marks a job as completed
func (jp *JobProcessor) completeJob(job *BackgroundJob) {
	job.Status = JobStatusCompleted
	now := time.Now()
	job.CompletedAt = &now

	// Move from processing to completed
	jp.moveJobToCompleted(job)

	log.Printf("Job %s completed successfully", job.ID)
}

// failJob marks a job as failed
func (jp *JobProcessor) failJob(job *BackgroundJob, err error) {
	job.Status = JobStatusFailed
	job.Error = err.Error()
	now := time.Now()
	job.CompletedAt = &now

	// Move from processing to failed
	jp.moveJobToFailed(job)

	log.Printf("Job %s failed: %v", job.ID, err)
}

// retryJob schedules a job for retry
func (jp *JobProcessor) retryJob(job *BackgroundJob, err error) {
	job.Status = JobStatusRetrying
	job.RetryCount++
	job.Error = err.Error()

	// Calculate retry delay (exponential backoff)
	delay := time.Duration(job.RetryCount*job.RetryCount) * time.Second
	job.ScheduledAt = time.Now().Add(delay)

	// Remove from processing and add to scheduled
	jp.removeJobFromProcessing(job)

	jobData, _ := json.Marshal(job)
	score := float64(job.ScheduledAt.Unix())
	jp.redis.ZAdd(jp.ctx, JobScheduledKey, &redis.Z{
		Score:  score,
		Member: jobData,
	})

	log.Printf("Job %s scheduled for retry %d in %v", job.ID, job.RetryCount, delay)
}

// scheduledJobProcessor moves scheduled jobs to the processing queue when ready
func (jp *JobProcessor) scheduledJobProcessor() {
	defer jp.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-jp.ctx.Done():
			return
		case <-ticker.C:
			now := float64(time.Now().Unix())

			// Get jobs that are ready to be processed
			jobs, err := jp.redis.ZRangeByScore(jp.ctx, JobScheduledKey, &redis.ZRangeBy{
				Min: "0",
				Max: fmt.Sprintf("%f", now),
			}).Result()

			if err != nil {
				log.Printf("Error getting scheduled jobs: %v", err)
				continue
			}

			// Move ready jobs to processing queue
			for _, jobData := range jobs {
				// Remove from scheduled
				jp.redis.ZRem(jp.ctx, JobScheduledKey, jobData)

				// Add to processing queue
				jp.redis.LPush(jp.ctx, JobQueueKey, jobData)
			}
		}
	}
}

// Helper methods for job queue management
func (jp *JobProcessor) findJobInList(ctx context.Context, listKey, jobID string) *BackgroundJob {
	jobs, err := jp.redis.LRange(ctx, listKey, 0, -1).Result()
	if err != nil {
		return nil
	}

	for _, jobData := range jobs {
		var job BackgroundJob
		if err := json.Unmarshal([]byte(jobData), &job); err != nil {
			continue
		}
		if job.ID == jobID {
			return &job
		}
	}

	return nil
}

func (jp *JobProcessor) updateJobInProcessing(job *BackgroundJob) {
	jobData, _ := json.Marshal(job)
	// This is a simplified update - in production, you'd want to find and replace the specific job
	jp.redis.LPush(jp.ctx, JobProcessingKey, jobData)
}

func (jp *JobProcessor) moveJobToCompleted(job *BackgroundJob) {
	jp.removeJobFromProcessing(job)
	jobData, _ := json.Marshal(job)
	jp.redis.LPush(jp.ctx, JobCompletedKey, jobData)
}

func (jp *JobProcessor) moveJobToFailed(job *BackgroundJob) {
	jp.removeJobFromProcessing(job)
	jobData, _ := json.Marshal(job)
	jp.redis.LPush(jp.ctx, JobFailedKey, jobData)
}

func (jp *JobProcessor) removeJobFromProcessing(job *BackgroundJob) {
	jobData, _ := json.Marshal(job)
	jp.redis.LRem(jp.ctx, JobProcessingKey, 1, jobData)
}

// Job Handlers

// MetricsAggregationHandler handles metrics aggregation jobs
type MetricsAggregationHandler struct{}

func (h *MetricsAggregationHandler) Handle(ctx context.Context, job *BackgroundJob) error {
	// Simulate metrics aggregation work
	time.Sleep(100 * time.Millisecond)
	log.Printf("Aggregated metrics for job %s", job.ID)
	return nil
}

// LogCleanupHandler handles log cleanup jobs
type LogCleanupHandler struct{}

func (h *LogCleanupHandler) Handle(ctx context.Context, job *BackgroundJob) error {
	// Simulate log cleanup work
	time.Sleep(200 * time.Millisecond)
	log.Printf("Cleaned up logs for job %s", job.ID)
	return nil
}

// ConfigSyncHandler handles configuration synchronization jobs
type ConfigSyncHandler struct{}

func (h *ConfigSyncHandler) Handle(ctx context.Context, job *BackgroundJob) error {
	// Simulate config sync work
	time.Sleep(150 * time.Millisecond)
	log.Printf("Synchronized configuration for job %s", job.ID)
	return nil
}

// HealthCheckHandler handles health check jobs
type HealthCheckHandler struct{}

func (h *HealthCheckHandler) Handle(ctx context.Context, job *BackgroundJob) error {
	// Simulate health check work
	time.Sleep(50 * time.Millisecond)
	log.Printf("Performed health check for job %s", job.ID)
	return nil
}

// DataExportHandler handles data export jobs
type DataExportHandler struct{}

func (h *DataExportHandler) Handle(ctx context.Context, job *BackgroundJob) error {
	// Simulate data export work
	time.Sleep(500 * time.Millisecond)
	log.Printf("Exported data for job %s", job.ID)
	return nil
}
