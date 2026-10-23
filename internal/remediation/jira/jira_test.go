package jira

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"tijeri/tests/contract"
)

func TestJiraAdapterContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/rest/api/2/issue" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"key": "PROJ-123"})
			return
		}
		if r.Method == "PUT" && r.URL.Path == "/rest/api/2/issue/PROJ-123" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/rest/api/2/issue/PROJ-123/transitions" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	
	adapter := NewAdapter(server.URL, "token", "PROJ")
	contract.RunTicketingAdapterContract(t, adapter)
}
