package servicenow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"tijeri/tests/contract"
)

func TestServiceNowAdapterContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/now/table/incident" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]string{"sys_id": "SYS-123"}})
			return
		}
		if r.Method == "PUT" && r.URL.Path == "/api/now/table/incident/SYS-123" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	
	adapter := NewAdapter(server.URL, "user", "pass")
	contract.RunTicketingAdapterContract(t, adapter)
}
