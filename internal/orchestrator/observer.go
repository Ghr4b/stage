package orchestrator

import (
	"fmt"
	"sync"
	"time"
)

// JobStatus represents the outcome of a scan job.
type JobStatus string

const (
	JobStatusRunning JobStatus = "running"
	JobStatusSuccess JobStatus = "success"
	JobStatusFailed  JobStatus = "failed"
	JobStatusTimeout JobStatus = "timeout"
)

// JobResult captures the full outcome of a scan job, including telemetry
// required to distinguish failure/timeout from zero findings (I12).
type JobResult struct {
	JobID         string
	AssetID       string
	Adapter       string
	Status        JobStatus
	FailureReason string // non-empty only when Status is failed/timeout
	FindingsCount int
	DurationMs    int64
	Timestamp     time.Time
}

// MetricEntry represents a single emitted metric for observability.
type MetricEntry struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// LogEntry represents a structured log line for a scan job.
type LogEntry struct {
	JobID         string    `json:"job_id"`
	AssetID       string    `json:"asset_id"`
	Adapter       string    `json:"adapter"`
	Status        string    `json:"status"`
	FailureReason string    `json:"failure_reason,omitempty"`
	FindingsCount int       `json:"findings_count"`
	DurationMs    int64     `json:"duration_ms"`
	Timestamp     time.Time `json:"timestamp"`
}

// Observer handles structured logging and metric emission for scan jobs.
type Observer struct {
	mu      sync.Mutex
	logs    []LogEntry
	metrics []MetricEntry
}

func NewObserver() *Observer {
	return &Observer{}
}

// RecordJobResult emits a structured log and Prometheus-style metrics for a job.
func (o *Observer) RecordJobResult(result JobResult) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Structured log
	entry := LogEntry{
		JobID:         result.JobID,
		AssetID:       result.AssetID,
		Adapter:       result.Adapter,
		Status:        string(result.Status),
		FailureReason: result.FailureReason,
		FindingsCount: result.FindingsCount,
		DurationMs:    result.DurationMs,
		Timestamp:     result.Timestamp,
	}
	o.logs = append(o.logs, entry)

	// Duration metric
	o.metrics = append(o.metrics, MetricEntry{
		Name: "scan_job_duration_seconds",
		Labels: map[string]string{
			"adapter": result.Adapter,
		},
		Value: float64(result.DurationMs) / 1000.0,
	})

	// Failure metric (only on failure)
	if result.Status == JobStatusFailed || result.Status == JobStatusTimeout {
		o.metrics = append(o.metrics, MetricEntry{
			Name: "scan_job_failures_total",
			Labels: map[string]string{
				"adapter": result.Adapter,
				"reason":  result.FailureReason,
			},
			Value: 1,
		})
	}
}

// Logs returns all recorded log entries (for testing).
func (o *Observer) Logs() []LogEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([]LogEntry, len(o.logs))
	copy(cp, o.logs)
	return cp
}

// Metrics returns all recorded metric entries (for testing).
func (o *Observer) Metrics() []MetricEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	cp := make([]MetricEntry, len(o.metrics))
	copy(cp, o.metrics)
	return cp
}

// FormatLogLine produces a human-readable log line for a result.
func FormatLogLine(r JobResult) string {
	if r.Status == JobStatusFailed || r.Status == JobStatusTimeout {
		return fmt.Sprintf("job_id=%s asset_id=%s adapter=%s status=%s reason=%s duration_ms=%d findings_count=%d",
			r.JobID, r.AssetID, r.Adapter, r.Status, r.FailureReason, r.DurationMs, r.FindingsCount)
	}
	return fmt.Sprintf("job_id=%s asset_id=%s adapter=%s status=%s duration_ms=%d findings_count=%d",
		r.JobID, r.AssetID, r.Adapter, r.Status, r.DurationMs, r.FindingsCount)
}
