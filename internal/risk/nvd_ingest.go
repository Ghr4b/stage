package risk

import "encoding/json"

type CisaADP struct {
	Metrics []struct {
		Other struct {
			Type    string `json:"type"`
			Content struct {
				Id      string `json:"id"`
				Options []struct {
					Automatable     string `json:"Automatable"`
					TechnicalImpact string `json:"Technical Impact"`
				} `json:"options"`
			} `json:"content"`
		} `json:"other"`
	} `json:"metrics"`
}

type NVDItem struct {
	CVE struct {
		ID       string `json:"id"`
		Metrics  map[string]interface{} `json:"metrics"`
		VendorComments []struct {
			Organization string `json:"organization"`
			Comment      string `json:"comment"`
		} `json:"vendorComments"`
	} `json:"cve"`
}

type ParsedVulnrichment struct {
	Automatable     bool
	TechnicalImpact bool // true for "total", false for "partial"
}

// ParseVulnrichment extracts SSVC decisions from CISA Vulnrichment ADP JSON.
func ParseVulnrichment(adpJSON []byte) (*ParsedVulnrichment, error) {
	var adp CisaADP
	if err := json.Unmarshal(adpJSON, &adp); err != nil {
		return nil, err
	}
	
	for _, m := range adp.Metrics {
		if m.Other.Type == "ssvc" {
			for _, opt := range m.Other.Content.Options {
				if opt.Automatable != "" || opt.TechnicalImpact != "" {
					result := &ParsedVulnrichment{
						Automatable:     opt.Automatable == "yes",
						TechnicalImpact: opt.TechnicalImpact == "total",
					}
					return result, nil
				}
			}
		}
	}
	
	return nil, nil // No SSVC data found
}
