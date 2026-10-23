package servicenow

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
	User    string
	Pass    string
	Client  *http.Client
}

func NewAdapter(baseURL, user, pass string) remediation.TicketingAdapter {
	return &Adapter{
		BaseURL: baseURL,
		User:    user,
		Pass:    pass,
		Client:  &http.Client{},
	}
}

func (a *Adapter) Name() string { return "servicenow" }

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
	
	req.SetBasicAuth(a.User, a.Pass)
	req.Header.Set("Content-Type", "application/json")
	
	return a.Client.Do(req)
}

func (a *Adapter) CreateTicket(ctx context.Context, f models.Finding) (string, error) {
	payload := map[string]interface{}{
		"short_description": fmt.Sprintf("Vuln %s in %s", f.VulnerabilityID, f.Component),
		"description":       "Automated ticket from platform",
		"category":          "security",
	}
	
	resp, err := a.doRequest(ctx, "POST", "/api/now/table/incident", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("servicenow api error: %d", resp.StatusCode)
	}
	
	var result struct {
		Result struct {
			SysID string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	return result.Result.SysID, nil
}

func (a *Adapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	resp, err := a.doRequest(ctx, "PUT", "/api/now/table/incident/"+ticketID, map[string]interface{}{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("servicenow api error: %d", resp.StatusCode)
	}
	return nil
}

func (a *Adapter) CloseTicket(ctx context.Context, ticketID string, reason string) error {
	payload := map[string]interface{}{
		"state": "7", // closed
		"close_notes": reason,
	}
	resp, err := a.doRequest(ctx, "PUT", "/api/now/table/incident/"+ticketID, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("servicenow api error: %d", resp.StatusCode)
	}
	return nil
}
