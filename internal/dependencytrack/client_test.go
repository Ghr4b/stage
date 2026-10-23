package dependencytrack

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("http://localhost:8080", "test-api-key")
	if client == nil {
		t.Errorf("Expected client to be non-nil")
	}
}

func TestUploadSBOM(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("X-Api-Key") != "test-api-key" {
			t.Errorf("Expected X-Api-Key to be test-api-key")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type to be application/json")
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		var payload map[string]string
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			t.Errorf("Failed to parse body: %v", err)
		}
		if payload["bom"] != "dGVzdC1zYm9t" { // base64 for "test-sbom"
			t.Errorf("Expected base64 encoded bom, got %s", payload["bom"])
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &dtClient{
		baseURL: server.URL,
		apiKey:  "test-api-key",
		http:    server.Client(),
	}

	err := client.UploadSBOM(context.Background(), "test-project", "1.0", []byte("test-sbom"))
	if err != nil {
		t.Errorf("Expected success, got %v", err)
	}
}

func TestUploadSBOMBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/version" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &dtClient{
		baseURL: server.URL,
		apiKey:  "test-api-key",
		http:    server.Client(),
	}

	err := client.UploadSBOM(context.Background(), "test-project", "1.0", []byte("test-sbom"))
	if err == nil {
		t.Errorf("Expected error on non-200/202 response")
	}
}
