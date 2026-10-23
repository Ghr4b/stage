package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefectDojoWebhook_FalsePositive(t *testing.T) {
	s := setupTestServer()
	
	payload := []byte(`{"finding_id": "f-123", "status": "False Positive"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/defectdojo", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	
	s.ServeHTTP(w, req)
	
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", w.Result().StatusCode)
	}
	
	if len(s.db.(*mockStore).logs) != 1 {
		t.Fatalf("Expected 1 audit log entry, got %d", len(s.db.(*mockStore).logs))
	}
	
	if s.db.(*mockStore).logs[0]["action"].(string) != "ml_feedback" {
		t.Errorf("Expected action 'ml_feedback', got '%s'", s.db.(*mockStore).logs[0]["action"].(string))
	}
}

func TestDefectDojoWebhook_OtherStatus(t *testing.T) {
	s := setupTestServer()
	
	payload := []byte(`{"finding_id": "f-124", "status": "Mitigated"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/defectdojo", bytes.NewBuffer(payload))
	w := httptest.NewRecorder()
	
	s.ServeHTTP(w, req)
	
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", w.Result().StatusCode)
	}
	
	// Should not trigger ML retraining
	if len(s.db.(*mockStore).logs) != 0 {
		t.Fatalf("Expected 0 audit log entries, got %d", len(s.db.(*mockStore).logs))
	}
}
