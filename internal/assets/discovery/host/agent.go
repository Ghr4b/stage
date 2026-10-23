package host

import (
	"context"
	"encoding/json"
)

type AgentConsumer struct {
	Publisher Publisher
}

type FleetHeartbeat struct {
	HostIdentifier string `json:"host_identifier"`
}

func (c *AgentConsumer) ProcessHeartbeat(ctx context.Context, payload []byte) (HostSignalEvent, error) {
	var hb FleetHeartbeat
	if err := json.Unmarshal(payload, &hb); err != nil {
		return HostSignalEvent{}, err
	}

	sig := HostSignalEvent{
		Type:            "agent_uuid",
		HostValue:       hb.HostIdentifier,
		ConfidenceScore: 1.0,
		Source:          "agent",
	}

	return sig, nil
}
