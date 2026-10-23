package defectdojo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"tijeri/internal/models"
	"time"
)

type Client struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

type DefectDojoFinding struct {
	ID                int    `json:"id,omitempty"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	Severity          string `json:"severity"`
	NumericalSeverity string `json:"numerical_severity"`
	FoundBy           []int  `json:"found_by"`
	UniqueIdFromTool  string `json:"unique_id_from_tool"`
	Test              int    `json:"test"`
	Active            bool   `json:"active"`
	Verified          bool   `json:"verified"`
}

type Product struct {
	ID          int    `json:"id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description"`
	ProdType    int    `json:"prod_type"`
}

type Engagement struct {
	ID                 int    `json:"id,omitempty"`
	Name               string `json:"name"`
	Product            int    `json:"product"`
	TargetStart        string `json:"target_start"`
	TargetEnd          string `json:"target_end"`
	EngagementType     string `json:"engagement_type"`
	Status             string `json:"status,omitempty"`
	DeduplicationOnEng bool   `json:"deduplication_on_engagement"`
}

type Test struct {
	ID          int    `json:"id,omitempty"`
	Title       string `json:"title"`
	Engagement  int    `json:"engagement"`
	TestType    int    `json:"test_type"`
	TargetStart string `json:"target_start"`
	TargetEnd   string `json:"target_end"`
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// doRequest is a helper that executes an authenticated request against the DefectDojo API.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// EnsureProductType creates the default "Tijeri" product type if it doesn't exist.
// Returns the product type ID.
func (c *Client) EnsureProductType(ctx context.Context) (int, error) {
	// Check if our product type already exists
	body, status, err := c.doRequest(ctx, "GET", "/api/v2/product_types/?name=Tijeri+Managed", nil)
	if err != nil {
		return 0, err
	}
	if status == 200 {
		var result struct {
			Count   int `json:"count"`
			Results []struct {
				ID int `json:"id"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &result); err == nil && result.Count > 0 {
			return result.Results[0].ID, nil
		}
	}

	// Create it
	payload := map[string]string{"name": "Tijeri Managed"}
	body, status, err = c.doRequest(ctx, "POST", "/api/v2/product_types/", payload)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("create product type failed (%d): %s", status, string(body))
	}
	var pt struct{ ID int `json:"id"` }
	if err := json.Unmarshal(body, &pt); err != nil {
		return 0, err
	}
	return pt.ID, nil
}

// EnsureProduct creates a DefectDojo Product for the given asset if it doesn't exist.
func (c *Client) EnsureProduct(ctx context.Context, asset models.Asset, prodTypeID int) (int, error) {
	// Search by name
	body, status, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/v2/products/?name=%s", asset.CanonicalName), nil)
	if err != nil {
		return 0, err
	}
	if status == 200 {
		var result struct {
			Count   int `json:"count"`
			Results []struct {
				ID int `json:"id"`
			} `json:"results"`
		}
		if err := json.Unmarshal(body, &result); err == nil && result.Count > 0 {
			return result.Results[0].ID, nil
		}
	}

	// Create product
	prod := Product{
		Name:        asset.CanonicalName,
		Description: fmt.Sprintf("Tijeri-managed asset: %s (type: %s, criticality: %s)", asset.AssetID, asset.Type, asset.CriticalityTier),
		ProdType:    prodTypeID,
	}
	body, status, err = c.doRequest(ctx, "POST", "/api/v2/products/", prod)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("create product failed (%d): %s", status, string(body))
	}
	var created Product
	if err := json.Unmarshal(body, &created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// EnsureAssetProduct ensures a DefectDojo Product exists for the asset so every
// discovered host appears in DefectDojo even when no findings are present.
func (c *Client) EnsureAssetProduct(ctx context.Context, asset models.Asset) (int, error) {
	ptID, err := c.EnsureProductType(ctx)
	if err != nil {
		return 0, err
	}
	return c.EnsureProduct(ctx, asset, ptID)
}

// EnsureEngagement creates an engagement for a scan run.
func (c *Client) EnsureEngagement(ctx context.Context, productID int, scannerName string) (int, error) {
	today := time.Now().Format("2006-01-02")
	eng := Engagement{
		Name:               fmt.Sprintf("Tijeri Continuous Scan - %s", scannerName),
		Product:            productID,
		TargetStart:        today,
		TargetEnd:          today,
		EngagementType:     "CI/CD",
		Status:             "In Progress",
		DeduplicationOnEng: true,
	}
	body, status, err := c.doRequest(ctx, "POST", "/api/v2/engagements/", eng)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("create engagement failed (%d): %s", status, string(body))
	}
	var created Engagement
	if err := json.Unmarshal(body, &created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// CreateTest creates a test under an engagement.
func (c *Client) CreateTest(ctx context.Context, engagementID int, scannerName string) (int, error) {
	today := time.Now().Format("2006-01-02")
	// Test type 1 is the generic "Manual Review" type that always exists in DefectDojo.
	t := Test{
		Title:       fmt.Sprintf("%s scan at %s", scannerName, time.Now().Format(time.RFC3339)),
		Engagement:  engagementID,
		TestType:    1,
		TargetStart: today,
		TargetEnd:   today,
	}
	body, status, err := c.doRequest(ctx, "POST", "/api/v2/tests/", t)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("create test failed (%d): %s", status, string(body))
	}
	var created Test
	if err := json.Unmarshal(body, &created); err != nil {
		return 0, err
	}
	return created.ID, nil
}

// PushFinding pushes a normalized finding to DefectDojo under a specific test.
func (c *Client) PushFinding(ctx context.Context, f models.Finding, testID int) (int, error) {
	severity := mapSeverity(f)

	ddFinding := DefectDojoFinding{
		Title:             fmt.Sprintf("%s in %s (%s)", f.VulnerabilityID, f.Component, f.ComponentVersion),
		Description:       fmt.Sprintf("Asset: %s\nTool: %s\nComponent: %s@%s\nFirst Seen: %s", f.AssetID, f.SourceTool, f.Component, f.ComponentVersion, f.FirstSeen.Format(time.RFC3339)),
		Severity:          severity,
		NumericalSeverity: mapNumericalSeverity(severity),
		FoundBy:           []int{1},
		UniqueIdFromTool:  f.DedupHash,
		Test:              testID,
		Active:            true,
		Verified:          false,
	}

	body, status, err := c.doRequest(ctx, "POST", "/api/v2/findings/", ddFinding)
	if err != nil {
		return 0, err
	}
	if status >= 400 {
		return 0, fmt.Errorf("push finding failed (%d): %s", status, string(body))
	}

	var result DefectDojoFinding
	if err := json.Unmarshal(body, &result); err != nil {
		return 0, err
	}
	return result.ID, nil
}

// PushBatch pushes an entire FindingsBatch into DefectDojo for a given asset and scanner.
// It handles the full Product → Engagement → Test → Findings hierarchy automatically.
func (c *Client) PushBatch(ctx context.Context, asset models.Asset, scannerName string, batch models.FindingsBatch) error {
	if len(batch.Findings) == 0 {
		return nil
	}

	ptID, err := c.EnsureProductType(ctx)
	if err != nil {
		return fmt.Errorf("ensure product type: %w", err)
	}

	prodID, err := c.EnsureProduct(ctx, asset, ptID)
	if err != nil {
		return fmt.Errorf("ensure product: %w", err)
	}

	engID, err := c.EnsureEngagement(ctx, prodID, scannerName)
	if err != nil {
		return fmt.Errorf("create engagement: %w", err)
	}

	testID, err := c.CreateTest(ctx, engID, scannerName)
	if err != nil {
		return fmt.Errorf("create test: %w", err)
	}

	pushed := 0
	for _, f := range batch.Findings {
		if _, err := c.PushFinding(ctx, f, testID); err != nil {
			fmt.Printf("  [DefectDojo] Warning: failed to push %s: %v\n", f.VulnerabilityID, err)
			continue
		}
		pushed++
	}

	fmt.Printf("  [DefectDojo] Pushed %d/%d findings from %s to product '%s'\n", pushed, len(batch.Findings), scannerName, asset.CanonicalName)
	return nil
}

// GetFinding retrieves a finding by its ID.
func (c *Client) GetFinding(ctx context.Context, id int) (*DefectDojoFinding, error) {
	body, status, err := c.doRequest(ctx, "GET", fmt.Sprintf("/api/v2/findings/%d/", id), nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("get finding failed (%d): %s", status, string(body))
	}
	var result DefectDojoFinding
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func mapSeverity(f models.Finding) string {
	if f.CVSS != nil {
		switch {
		case f.CVSS.Score >= 9.0:
			return "Critical"
		case f.CVSS.Score >= 7.0:
			return "High"
		case f.CVSS.Score >= 4.0:
			return "Medium"
		case f.CVSS.Score > 0:
			return "Low"
		}
	}
	return "Info"
}

func mapNumericalSeverity(severity string) string {
	switch severity {
	case "Critical":
		return "S4"
	case "High":
		return "S3"
	case "Medium":
		return "S2"
	case "Low":
		return "S1"
	}
	return "S0"
}
