package normalize

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"tijeri/internal/models"
)

type mockObjStore struct {
	data map[string][]byte
}

func (m *mockObjStore) Put(ctx context.Context, key string, data []byte) error {
	m.data[key] = data
	return nil
}
func (m *mockObjStore) Get(ctx context.Context, key string) ([]byte, error) {
	return m.data[key], nil
}

func TestWriteVEXDocument(t *testing.T) {
	mStore := &mockObjStore{data: make(map[string][]byte)}

	f := &models.Finding{
		FindingID:       "f-999",
		VulnerabilityID: "CVE-2026-9999",
		Component:       "test-pkg",
	}

	err := WriteVEXDocument(context.Background(), f, mStore)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	var savedKey string
	var savedData []byte
	for k, v := range mStore.data {
		savedKey = k
		savedData = v
		break
	}

	if savedKey == "" {
		t.Fatal("Expected document to be saved in mock object store")
	}

	if !strings.HasPrefix(savedKey, "vex/generated/CVE-2026-9999/") {
		t.Errorf("Expected key prefix vex/generated/CVE-2026-9999/, got %s", savedKey)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(savedData, &doc); err != nil {
		t.Fatal(err)
	}

	if doc["@context"] != "https://openvex.dev/ns/v0.2.0" {
		t.Errorf("Expected @context to be openvex, got %v", doc["@context"])
	}

	statements := doc["statements"].([]interface{})
	if len(statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(statements))
	}
	stmt := statements[0].(map[string]interface{})

	if stmt["status"] != "not_affected" {
		t.Errorf("Expected status to be 'not_affected', got %v", stmt["status"])
	}
	if stmt["justification"] != "vulnerable_code_not_in_execute_path" {
		t.Errorf("Expected justification 'vulnerable_code_not_in_execute_path', got %v", stmt["justification"])
	}
}
