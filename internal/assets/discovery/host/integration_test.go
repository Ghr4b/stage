package host

import (
	"context"
	"testing"
	"time"
)

func TestIntegrationScanAverseHost(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Simulated scan-averse host IP (TEST-NET-1, usually blackholed/unreachable)
	scanAverseIP := "192.0.2.1"

	active := &ActiveScanner{}
	passive := &PassiveObserver{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Active scanner should fail to discover the host
	_, err := active.Scan(ctx, scanAverseIP)
	if err == nil {
		t.Logf("Warning: nmap actually found %s, which is unexpected for a scan-averse IP in this environment", scanAverseIP)
	} else {
		t.Logf("Active scan successfully failed (as expected) for firewalled host: %v", err)
	}

	// 2. Passive scanner should succeed in discovering it via simulated NetFlow/Zeek log
	zeekLog := []byte(`{"id.orig_h": "192.0.2.1"}`)
	sig, err := passive.ProcessLog(context.Background(), zeekLog)
	if err != nil {
		t.Fatalf("Passive observer failed to process log: %v", err)
	}

	if sig.HostValue != scanAverseIP {
		t.Errorf("Expected passive observer to discover %s, got %s", scanAverseIP, sig.HostValue)
	}

	t.Logf("Passive observer successfully discovered firewalled host: %s", sig.HostValue)
}
