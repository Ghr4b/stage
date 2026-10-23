package orchestrator

import (
	"testing"
	"time"
)

func TestSilentFailureObservability(t *testing.T) {
	observer := NewObserver()

	// Simulate a timed-out adapter run
	timeoutResult := JobResult{
		JobID:         "job-timeout-1",
		AssetID:       "asset-1",
		Adapter:       "greenbone",
		Status:        JobStatusTimeout,
		FailureReason: "timeout",
		FindingsCount: 0,
		DurationMs:    300000,
		Timestamp:     time.Now(),
	}

	// Simulate a successful run with zero findings
	successResult := JobResult{
		JobID:         "job-success-1",
		AssetID:       "asset-2",
		Adapter:       "greenbone",
		Status:        JobStatusSuccess,
		FailureReason: "",
		FindingsCount: 0,
		DurationMs:    5000,
		Timestamp:     time.Now(),
	}

	observer.RecordJobResult(timeoutResult)
	observer.RecordJobResult(successResult)

	logs := observer.Logs()
	metrics := observer.Metrics()

	// Assert: the two states are distinct in the emitted telemetry
	if len(logs) != 2 {
		t.Fatalf("Expected 2 log entries, got %d", len(logs))
	}

	timeoutLog := logs[0]
	successLog := logs[1]

	// Status must differ
	if timeoutLog.Status == successLog.Status {
		t.Errorf("Timeout and success states must have different status values, both got %s", timeoutLog.Status)
	}

	if timeoutLog.Status != "timeout" {
		t.Errorf("Expected timeout log status 'timeout', got %s", timeoutLog.Status)
	}
	if successLog.Status != "success" {
		t.Errorf("Expected success log status 'success', got %s", successLog.Status)
	}

	// Timeout must have a failure reason
	if timeoutLog.FailureReason == "" {
		t.Error("Timeout log must have a non-empty failure_reason")
	}

	// Success must NOT have a failure reason
	if successLog.FailureReason != "" {
		t.Error("Success log must have an empty failure_reason")
	}

	// Metrics: timeout should emit a failure metric, success should not
	failureMetrics := 0
	for _, m := range metrics {
		if m.Name == "scan_job_failures_total" {
			failureMetrics++
			if m.Labels["reason"] != "timeout" {
				t.Errorf("Expected failure metric reason 'timeout', got %s", m.Labels["reason"])
			}
		}
	}
	if failureMetrics != 1 {
		t.Errorf("Expected exactly 1 failure metric (from timeout), got %d", failureMetrics)
	}

	// Both should emit duration metrics
	durationMetrics := 0
	for _, m := range metrics {
		if m.Name == "scan_job_duration_seconds" {
			durationMetrics++
		}
	}
	if durationMetrics != 2 {
		t.Errorf("Expected 2 duration metrics (one per job), got %d", durationMetrics)
	}

	// Log line formatting must also distinguish them
	timeoutLine := FormatLogLine(timeoutResult)
	successLine := FormatLogLine(successResult)

	if timeoutLine == successLine {
		t.Error("Formatted log lines for timeout and success must differ")
	}
}
