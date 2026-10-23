package jira

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
	BaseURL    string
	AuthToken  string
	ProjectKey string
	Client     *http.Client
}

func NewAdapter(baseURL, authToken, projectKey string) remediation.TicketingAdapter {
	return &Adapter{
		BaseURL:    baseURL,
		AuthToken:  authToken,
		ProjectKey: projectKey,
		Client:     &http.Client{},
	}
}

func (a *Adapter) Name() string { return "jira" }

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
	
	req.Header.Set("Authorization", "Bearer "+a.AuthToken)
	req.Header.Set("Content-Type", "application/json")
	
	return a.Client.Do(req)
}

func (a *Adapter) CreateTicket(ctx context.Context, f models.Finding) (string, error) {
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{"key": a.ProjectKey},
			"summary": fmt.Sprintf("Vulnerability %s in %s", f.VulnerabilityID, f.Component),
			"description": "Automated ticket from platform",
			"issuetype": map[string]string{"name": "Bug"},
		},
	}
	
	resp, err := a.doRequest(ctx, "POST", "/rest/api/2/issue", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("jira api error: %d", resp.StatusCode)
	}
	
	var result struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	
	return result.Key, nil
}

func (a *Adapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	// Simplified update logic for demonstration
	resp, err := a.doRequest(ctx, "PUT", "/rest/api/2/issue/"+ticketID, map[string]interface{}{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("jira api error: %d", resp.StatusCode)
	}
	return nil
}

func (a *Adapter) CloseTicket(ctx context.Context, ticketID string, reason string) error {
	// Simplified transition logic
	resp, err := a.doRequest(ctx, "POST", "/rest/api/2/issue/"+ticketID+"/transitions", map[string]interface{}{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("jira api error: %d", resp.StatusCode)
	}
	return nil
}
