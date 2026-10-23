package wazuh

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type MockPublisher struct {
	PublishedSubject string
	PublishedData    []byte
}

func (m *MockPublisher) Publish(subject string, data []byte) error {
	m.PublishedSubject = subject
	m.PublishedData = data
	return nil
}

func TestWazuhReceiverIntegration(t *testing.T) {
	mockPub := &MockPublisher{}
	receiver := &Receiver{Publisher: mockPub}
	
	// Create a test server
	server := httptest.NewServer(receiver)
	defer server.Close()

	// Fixture payload simulating Wazuh syscollector
	payload := []byte(`{
		"agent": {
			"id": "001",
			"name": "web-server-01",
			"ip": "10.0.0.50"
		},
		"syscheck": {
			"mac": "00:1A:2B:3C:4D:5E"
		},
		"os": {
			"name": "Ubuntu 22.04 LTS"
		}
	}`)

	resp, err := http.Post(server.URL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("Failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status OK, got %v", resp.StatusCode)
	}

	// Verify the signal was published correctly
	if mockPub.PublishedSubject != "signals.wazuh" {
		t.Errorf("Expected subject signals.wazuh, got %s", mockPub.PublishedSubject)
	}

	var sig WazuhSignalEvent
	if err := json.Unmarshal(mockPub.PublishedData, &sig); err != nil {
		t.Fatalf("Failed to unmarshal published data: %v", err)
	}

	if sig.AgentID != "001" || sig.AgentName != "web-server-01" || sig.AgentIP != "10.0.0.50" || sig.MACAddress != "00:1A:2B:3C:4D:5E" || sig.OSName != "Ubuntu 22.04 LTS" {
		t.Errorf("Signal fields did not match fixture: %+v", sig)
	}
}
