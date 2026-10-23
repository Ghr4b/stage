package wazuh

import (
	"encoding/json"
	"io"
	"net/http"
)

type Publisher interface {
	Publish(subject string, data []byte) error
}

type Receiver struct {
	Publisher Publisher
}

// SyscollectorPayload represents a simplified Wazuh syscollector event
type SyscollectorPayload struct {
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
	Syscheck struct {
		MAC string `json:"mac"`
	} `json:"syscheck,omitempty"` // Example field
	OS struct {
		Name string `json:"name"`
	} `json:"os,omitempty"`
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	var payload SyscollectorPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	sig := WazuhSignalEvent{
		AgentID:         payload.Agent.ID,
		AgentName:       payload.Agent.Name,
		AgentIP:         payload.Agent.IP,
		MACAddress:      payload.Syscheck.MAC,
		OSName:          payload.OS.Name,
		ConfidenceScore: 1.0,
		Source:          "wazuh",
	}

	sigBytes, _ := json.Marshal(sig)
	
	if r.Publisher != nil {
		err = r.Publisher.Publish("signals.wazuh", sigBytes)
		if err != nil {
			http.Error(w, "Error publishing signal", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}
