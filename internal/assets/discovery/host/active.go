package host

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
)

type ActiveScanner struct {
	Publisher Publisher
}

type Publisher interface {
	Publish(subject string, data []byte) error
}

func (s *ActiveScanner) Scan(ctx context.Context, target string) ([]HostSignalEvent, error) {
	// Wrapper around nmap -sn
	cmd := exec.CommandContext(ctx, "nmap", "-sn", target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// If it's a timeout or nmap fails completely
		return nil, errors.New("scan failed or timed out")
	}

	// Very naive nmap output parser for test purposes
	var signals []HostSignalEvent
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Nmap scan report for") {
			parts := strings.Split(line, " ")
			if len(parts) >= 5 {
				ip := parts[4]
				ip = strings.Trim(ip, "()")
				signals = append(signals, HostSignalEvent{
					Type:            "ip",
					HostValue:       ip,
					ConfidenceScore: 0.9,
					Source:          "active",
				})
			}
		}
	}
	
	if len(signals) == 0 {
		return nil, errors.New("host seems down or firewalled")
	}

	return signals, nil
}
