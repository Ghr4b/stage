package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewClientRequiresToken(t *testing.T) {
	os.Unsetenv("VAULT_TOKEN")
	_, err := NewClient()
	if err == nil {
		t.Errorf("Expected error when VAULT_TOKEN is empty")
	}
}

func TestNewClientSucceedsWithToken(t *testing.T) {
	os.Setenv("VAULT_TOKEN", "test-token")
	defer os.Unsetenv("VAULT_TOKEN")
	client, err := NewClient()
	if err != nil {
		t.Errorf("Expected success, got %v", err)
	}
	if client == nil {
		t.Errorf("Expected client to be non-nil")
	}
}

func TestGetSecretBadStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := &vaultClient{
		addr:  server.URL,
		token: "test-token",
		http:  server.Client(),
	}

	_, err := client.GetSecret(context.Background(), "secret/test")
	if err == nil {
		t.Errorf("Expected error on non-200 response")
	}
}
