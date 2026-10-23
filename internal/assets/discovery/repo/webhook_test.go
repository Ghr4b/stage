package repo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type MockPublisher struct {
	PublishedData []byte
	Subject       string
}

func (m *MockPublisher) Publish(subject string, data []byte) error {
	m.Subject = subject
	m.PublishedData = data
	return nil
}

func TestWebhookHandler(t *testing.T) {
	mockPub := &MockPublisher{}
	handler := &WebhookHandler{
		Publisher: mockPub,
		Subject:   "signals.repo",
	}

	payload := []byte(`{
		"repository": {
			"clone_url": "https://github.com/tijeri/testrepo.git"
		},
		"commits": [
			{
				"added": ["package.json"],
				"modified": ["src/main.go", "go.mod"]
			}
		]
	}`)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(w, req)
	duration := time.Since(start)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d", w.Code)
	}

	if duration > 500*time.Millisecond {
		t.Fatalf("Expected processing within 500ms, took %v", duration)
	}

	if mockPub.Subject != "signals.repo" {
		t.Errorf("Expected subject 'signals.repo', got '%s'", mockPub.Subject)
	}

	var sig RepoSignalEvent
	if err := json.Unmarshal(mockPub.PublishedData, &sig); err != nil {
		t.Fatalf("Failed to parse published signal: %v", err)
	}

	if sig.URL != "https://github.com/tijeri/testrepo.git" {
		t.Errorf("Expected URL to match, got %s", sig.URL)
	}

	if len(sig.Ecosystems) != 2 {
		t.Fatalf("Expected 2 ecosystems, got %d", len(sig.Ecosystems))
	}

	// Ecosystem order might not be deterministic based on maps in DetectEcosystems,
	// but let's check both are present.
	ecoMap := make(map[string]bool)
	for _, eco := range sig.Ecosystems {
		ecoMap[eco] = true
	}

	if !ecoMap["npm"] || !ecoMap["go"] {
		t.Errorf("Expected npm and go ecosystems, got %v", sig.Ecosystems)
	}
}
