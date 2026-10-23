package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"tijeri/internal/models"
)

type WazuhFIMEvent struct {
	Syscheck struct {
		Path  string `json:"path"`
		Event string `json:"event"`
	} `json:"syscheck"`
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
}

func (s *Server) handleWazuhWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var event WazuhFIMEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if event.Agent.ID == "" || event.Agent.Name == "" || net.ParseIP(event.Agent.IP) == nil {
		http.Error(w, "Agent ID, name, and valid IP are required", http.StatusBadRequest)
		return
	}
	if allowed, reason := isTargetAllowed(event.Agent.IP); !allowed {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	if s.publisher == nil {
		http.Error(w, "Event queue unavailable", http.StatusServiceUnavailable)
		return
	}

	asset := models.Asset{
		AssetID:       fmt.Sprintf("wazuh-agent-%s", event.Agent.ID),
		CanonicalName: event.Agent.Name,
		Type:          "host",
		Metadata: map[string]string{
			"wazuh_agent_id": event.Agent.ID,
			"ip":             event.Agent.IP,
			"fim_path":       event.Syscheck.Path,
			"fim_event":      event.Syscheck.Event,
		},
	}
	data, err := json.Marshal(asset)
	if err != nil {
		http.Error(w, "Could not encode scan request", http.StatusInternalServerError)
		return
	}
	if err := s.db.SaveAuditLog(r.Context(), "wazuh_rescan_queued", "wazuh-webhook", asset.AssetID, "Targeted scan requested from Wazuh FIM event"); err != nil {
		http.Error(w, "Could not persist audit event", http.StatusInternalServerError)
		return
	}
	if err := s.publisher.Publish("tijeri.scan.requested", data); err != nil {
		http.Error(w, "Could not queue scan request", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted","action":"rescan_queued"}`))
}
