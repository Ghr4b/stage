package dependencytrack

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// Client provides an interface to OWASP Dependency-Track
type Client interface {
	UploadSBOM(ctx context.Context, projectName, projectVersion string, sbomBytes []byte) error
}

type dtClient struct {
	baseURL string
	apiKey  string
	http    *http.Client

	mu        sync.Mutex
	healthOK  bool
}

func NewClient(baseURL, apiKey string) Client {
	return &dtClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// waitReady blocks until the Dependency-Track API responds on its version
// endpoint (an auth-free liveness check signalling the server has finished
// booting). It honors ctx and gives up after maxWait.
func (c *dtClient) waitReady(ctx context.Context, maxWait time.Duration) error {
	deadline := time.Now().Add(maxWait)
	versionURL := fmt.Sprintf("%s/api/version", c.baseURL)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("dependency-track not reachable after %s", maxWait)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *dtClient) UploadSBOM(ctx context.Context, projectName, projectVersion string, sbomBytes []byte) error {
	url := fmt.Sprintf("%s/api/v1/bom", c.baseURL)

	// Once known to be up, don't re-check on every call.
	c.mu.Lock()
	needHealth := !c.healthOK
	c.mu.Unlock()
	if needHealth {
		if err := c.waitReady(ctx, 60*time.Second); err != nil {
			return err
		}
		c.mu.Lock()
		c.healthOK = true
		c.mu.Unlock()
	}

	encodedSBOM := base64.StdEncoding.EncodeToString(sbomBytes)

	payload := map[string]string{
		"projectName":    projectName,
		"projectVersion": projectVersion,
		"autoCreate":     "true",
		"bom":            encodedSBOM,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var lastErr error
	for attempts := 1; attempts <= 3; attempts++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("X-Api-Key", c.apiKey)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempts) * time.Second)
			continue
		}
		
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			resp.Body.Close()
			return fmt.Errorf("dependency-track auth failed: %d", resp.StatusCode)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			resp.Body.Close()
			lastErr = fmt.Errorf("dependency-track returned status: %d", resp.StatusCode)
			time.Sleep(time.Duration(attempts) * time.Second)
			continue
		}
		
		resp.Body.Close()
		return nil
	}

	return fmt.Errorf("failed to upload SBOM after 3 attempts: %v", lastErr)
}
