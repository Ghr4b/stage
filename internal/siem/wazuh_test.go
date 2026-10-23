package siem

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCDBListGenerator(t *testing.T) {
	ips := []string{"10.0.1.42", "192.168.1.100"}
	cdb := GenerateCDBList(ips)
	
	expected := "10.0.1.42:vulnerable\n192.168.1.100:vulnerable\n"
	if cdb != expected {
		t.Errorf("Expected:\n%s\nGot:\n%s", expected, cdb)
	}
}

func TestWazuhCorrelationRule(t *testing.T) {
	cdb := map[string]string{
		"10.0.1.42": "vulnerable",
	}
	
	if severity := EvaluateAlert("10.0.1.42", cdb); severity != 12 {
		t.Errorf("Expected escalated severity 12 for CDB match, got %d", severity)
	}
	
	if severity := EvaluateAlert("192.168.1.100", cdb); severity != 3 {
		t.Errorf("Expected normal severity 3 for non-match, got %d", severity)
	}
}

func TestNoSynchronousBottleneck(t *testing.T) {
	// P8-3: Load test verifying no blocking network call exists in the per-alert evaluation path
	start := time.Now()
	
	cdb := map[string]string{
		"10.0.1.42": "vulnerable",
	}
	
	for i := 0; i < 100000; i++ {
		EvaluateAlert("10.0.1.42", cdb)
	}
	
	duration := time.Since(start)
	if duration > 50*time.Millisecond {
		t.Errorf("Latency regression: 100k evaluations took %v, which suggests a bottleneck", duration)
	}
}

// Named test (I10)
func TestFailOpenNeverSuppressesOnError(t *testing.T) {
	ctx := context.Background()
	originalSeverity := 3
	
	// Simulated error path (e.g. timeout)
	failingCall := func(ctx context.Context, ip string) (bool, error) {
		return false, errors.New("network timeout")
	}
	
	resultSeverity := OnDemandLookup(ctx, "10.0.1.50", originalSeverity, failingCall)
	
	if resultSeverity != originalSeverity {
		t.Errorf("I10 violated: expected fail-open with original severity %d, got %d", originalSeverity, resultSeverity)
	}
	
	if resultSeverity == 0 {
		t.Error("I10 violated: alert was silently suppressed (severity 0)")
	}
}
