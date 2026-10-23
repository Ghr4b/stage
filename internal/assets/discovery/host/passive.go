package host

import (
	"context"
	"encoding/json"
)

type PassiveObserver struct {
	Publisher Publisher
}

type ZeekConnLog struct {
	IdOrigH string `json:"id.orig_h"`
}

func (o *PassiveObserver) ProcessLog(ctx context.Context, payload []byte) (HostSignalEvent, error) {
	var log ZeekConnLog
	if err := json.Unmarshal(payload, &log); err != nil {
		return HostSignalEvent{}, err
	}
	
	sig := HostSignalEvent{
		Type:            "ip",
		HostValue:       log.IdOrigH,
		ConfidenceScore: 1.0, // passive traffic is highly confident the host exists
		Source:          "passive",
	}

	return sig, nil
}
