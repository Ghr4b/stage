package directory

import (
	"context"
	"encoding/json"
	"errors"
)

type ADConnector struct {
	Publisher Publisher
}

type Publisher interface {
	Publish(subject string, data []byte) error
}

// ADComputer represents a simplified Active Directory computer object returned by a mock API
type ADComputer struct {
	ObjectSID string `json:"object_sid"`
	DNSHostName string `json:"dns_host_name"`
	OperatingSystem string `json:"operating_system"`
}

func (c *ADConnector) ProcessADExport(ctx context.Context, payload []byte) (DirectorySignalEvent, error) {
	var computer ADComputer
	if err := json.Unmarshal(payload, &computer); err != nil {
		return DirectorySignalEvent{}, err
	}

	if computer.ObjectSID == "" {
		return DirectorySignalEvent{}, errors.New("missing object_sid in AD export")
	}

	sig := DirectorySignalEvent{
		ObjectSID:       computer.ObjectSID,
		Hostname:        computer.DNSHostName,
		Attributes:      map[string]string{"os": computer.OperatingSystem},
		ConfidenceScore: 1.0,
		Source:          "active_directory",
	}

	return sig, nil
}
