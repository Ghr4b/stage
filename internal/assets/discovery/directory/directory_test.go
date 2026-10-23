package directory

import (
	"context"
	"testing"
)

func TestADConnectorParsing(t *testing.T) {
	connector := &ADConnector{}
	
	// Mock AD API response
	payload := []byte(`{
		"object_sid": "S-1-5-21-3623811015-3361044348-30300820-1013",
		"dns_host_name": "server01.corp.local",
		"operating_system": "Windows Server 2019"
	}`)

	sig, err := connector.ProcessADExport(context.Background(), payload)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Integration/Unit requirement: Domain SID, not hostname, is the primary key extracted for AD-sourced signals
	if sig.SignalType() != "domain_sid" {
		t.Errorf("Expected identity type domain_sid, got %s", sig.SignalType())
	}

	if sig.Value() != "S-1-5-21-3623811015-3361044348-30300820-1013" {
		t.Errorf("Expected value to be ObjectSID, got %s", sig.Value())
	}

	if sig.Value() == "server01.corp.local" {
		t.Errorf("CRITICAL: Identity key was hostname instead of Domain SID!")
	}
}
