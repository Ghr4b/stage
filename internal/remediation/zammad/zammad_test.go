package zammad

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"tijeri/tests/contract"
)

func TestZammadAdapterContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/v1/tickets" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]int{"id": 42})
			return
		}
		if r.Method == "PUT" && r.URL.Path == "/api/v1/tickets/42" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	
	adapter := NewAdapter(server.URL, "token")
	contract.RunTicketingAdapterContract(t, adapter)
}
