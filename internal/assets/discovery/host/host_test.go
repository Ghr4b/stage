package host

import (
	"context"
	"testing"
)

func TestPassiveObserver(t *testing.T) {
	observer := &PassiveObserver{}
	payload := []byte(`{"id.orig_h": "10.0.0.5"}`)
	
	sig, err := observer.ProcessLog(context.Background(), payload)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sig.Type != "ip" || sig.HostValue != "10.0.0.5" || sig.Source != "passive" {
		t.Errorf("Incorrect signal generated: %+v", sig)
	}
}

func TestAgentConsumer(t *testing.T) {
	consumer := &AgentConsumer{}
	payload := []byte(`{"host_identifier": "fleet-uuid-1234"}`)

	sig, err := consumer.ProcessHeartbeat(context.Background(), payload)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sig.Type != "agent_uuid" || sig.HostValue != "fleet-uuid-1234" || sig.Source != "agent" {
		t.Errorf("Incorrect signal generated: %+v", sig)
	}
}
