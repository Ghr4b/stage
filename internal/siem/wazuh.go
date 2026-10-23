package siem

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GenerateCDBList produces a Wazuh CDB (Constant DataBase) list of vulnerable IPs.
// Format is: key:value (e.g., 10.0.1.42:vulnerable)
func GenerateCDBList(vulnerableIPs []string) string {
	var sb strings.Builder
	for _, ip := range vulnerableIPs {
		sb.WriteString(fmt.Sprintf("%s:vulnerable\n", ip))
	}
	return sb.String()
}

// EvaluateAlert represents the Wazuh correlation rule logic inside the Go harness.
func EvaluateAlert(alertIP string, cdb map[string]string) (severity int) {
	if cdb[alertIP] == "vulnerable" {
		return 12 // Escalated severity
	}
	return 3 // Normal severity
}

// OnDemandLookup is the fallback path (P8-4) if the IP is not in the CDB list but needs a synchronous check.
// I10: Fail-open guarantee - if this fails, we return the original severity unmodified, NOT zero.
func OnDemandLookup(ctx context.Context, alertIP string, originalSeverity int, doNetworkCall func(context.Context, string) (bool, error)) int {
	// Apply timeout circuit breaker
	ctxTimeout, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	
	isVulnerable, err := doNetworkCall(ctxTimeout, alertIP)
	if err != nil {
		// I10: explicit fail-open.
		if errors.Is(err, context.DeadlineExceeded) || err != nil {
			return originalSeverity // pass through unmodified
		}
	}
	
	if isVulnerable {
		return 12 // Escalated
	}
	
	return originalSeverity
}
