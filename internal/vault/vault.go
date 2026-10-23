package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Client provides an interface to OpenBao / HashiCorp Vault.
type Client interface {
	GetSecret(ctx context.Context, path string) (map[string]interface{}, error)
}

type vaultClient struct {
	addr  string
	token string
	http  *http.Client
}

func NewClient() (Client, error) {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://localhost:8200"
	}
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required")
	}

	return &vaultClient{
		addr:  addr,
		token: token,
		http: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

func (c *vaultClient) GetSecret(ctx context.Context, path string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/v1/%s", c.addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned status: %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data.Data, nil
}
