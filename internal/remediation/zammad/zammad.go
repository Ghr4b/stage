package zammad

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

type Adapter struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func NewAdapter(baseURL, token string) remediation.TicketingAdapter {
	return &Adapter{
		BaseURL: baseURL,
		Token:   token,
		Client:  &http.Client{},
	}
}

func (a *Adapter) Name() string { return "zammad" }

func (a *Adapter) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, &buf)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Token token="+a.Token)
	req.Header.Set("Content-Type", "application/json")
	
	return a.Client.Do(req)
}

func (a *Adapter) CreateTicket(ctx context.Context, f models.Finding) (string, error) {
	payload := map[string]interface{}{
		"title": fmt.Sprintf("Vuln %s in %s", f.VulnerabilityID, f.Component),
		"group": "Security",
		"article": map[string]interface{}{
			"body": "Automated ticket from platform",
			"type": "note",
			"internal": false,
		},
	}
	
	resp, err := a.doRequest(ctx, "POST", "/api/v1/tickets", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("zammad api error: %d", resp.StatusCode)
	}
	
	var result struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	return fmt.Sprintf("%d", result.ID), nil
}

func (a *Adapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	resp, err := a.doRequest(ctx, "PUT", "/api/v1/tickets/"+ticketID, map[string]interface{}{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("zammad api error: %d", resp.StatusCode)
	}
	return nil
}

func (a *Adapter) CloseTicket(ctx context.Context, ticketID string, reason string) error {
	payload := map[string]interface{}{
		"state": "closed",
	}
	resp, err := a.doRequest(ctx, "PUT", "/api/v1/tickets/"+ticketID, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("zammad api error: %d", resp.StatusCode)
	}
	return nil
}
