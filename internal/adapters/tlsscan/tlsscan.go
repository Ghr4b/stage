package tlsscan

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

// SslyzeOutput represents the top-level sslyze 5.x JSON output structure.
type SslyzeOutput struct {
	ServerScanResults []struct {
		ServerLocation struct {
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
		} `json:"server_location"`
		ScanResult struct {
			TLS10CipherSuites struct {
				Result struct {
					TLSVersionUsed     string `json:"tls_version_used"`
					IsTLSVersionSupported bool `json:"is_tls_version_supported"`
					AcceptedCipherSuites []CipherSuiteEntry `json:"accepted_cipher_suites"`
				} `json:"result"`
			} `json:"tls_1_0_cipher_suites"`
			TLS11CipherSuites struct {
				Result struct {
					TLSVersionUsed     string `json:"tls_version_used"`
					IsTLSVersionSupported bool `json:"is_tls_version_supported"`
					AcceptedCipherSuites []CipherSuiteEntry `json:"accepted_cipher_suites"`
				} `json:"result"`
			} `json:"tls_1_1_cipher_suites"`
			TLS12CipherSuites struct {
				Result struct {
					TLSVersionUsed     string `json:"tls_version_used"`
					IsTLSVersionSupported bool `json:"is_tls_version_supported"`
					AcceptedCipherSuites []CipherSuiteEntry `json:"accepted_cipher_suites"`
				} `json:"result"`
			} `json:"tls_1_2_cipher_suites"`
			TLSCompression struct {
				Result struct {
					SupportsCompression bool `json:"supports_compression"`
				} `json:"result"`
			} `json:"tls_compression"`
			Hearbleed struct {
				Result struct {
					IsVulnerableToHeartbleed bool `json:"is_vulnerable_to_heartbleed"`
				} `json:"result"`
			} `json:"heartbleed"`
			CCSInjection struct {
				Result struct {
					IsVulnerableToCCSInjection bool `json:"is_vulnerable_to_ccs_injection"`
				} `json:"result"`
			} `json:"openssl_ccs_injection"`
			SessionRenegotiation struct {
				Result struct {
					IsVulnerableToClientRenegotiationDoS bool `json:"is_vulnerable_to_client_renegotiation_dos"`
				} `json:"result"`
			} `json:"session_renegotiation"`
			CertificateInfo struct {
				Result struct {
					CertificateDeployments []struct {
						ReceivedCertificateChain []struct {
							NotValidBefore string   `json:"not_valid_before"`
							NotValidAfter  string   `json:"not_valid_after"`
							SubjectDn      []string `json:"subject_dn"`
							IssuerDn       []string `json:"issuer_dn"`
						} `json:"received_certificate_chain"`
					} `json:"certificate_deployments"`
				} `json:"result"`
			} `json:"certificate_info"`
		} `json:"scan_result"`
	} `json:"server_scan_results"`
}

// CipherSuiteEntry is one accepted cipher suite in sslyze output.
type CipherSuiteEntry struct {
	CipherSuite struct {
		Name        string `json:"name"`
		KeySize     int    `json:"key_size"`
		IsAnonymous bool   `json:"is_anonymous"`
	} `json:"cipher_suite"`
}

type Config struct {
	BinPath string // Override binary path (default: "sslyze")
	Ports   []int  // Ports to probe; defaults to common TLS listener ports
}

// defaultPorts covers implicit TLS + StartTLS (ldap/smtp/imap/pop3) services.
var defaultPorts = []int{443, 636, 8443, 9443, 993, 995, 389, 25, 587, 143, 110, 465}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "tlsscan" }

func (a *Adapter) Supports(asset models.Asset) bool {
	return asset.Type == "host"
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	// Use canonical name (which should be the hostname) if available
	target := asset.CanonicalName
	if target == "" {
		target = asset.Metadata["host"]
	}
	if target == "" {
		return models.FindingsBatch{}, nil
	}

	// Probe common TLS listener ports; scan every reachable one.
	ports := a.Config.Ports
	if len(ports) == 0 {
		ports = defaultPorts
	}
	openPorts := a.probeTLSPorts(ctx, target, ports)

	var all models.FindingsBatch
	for _, port := range openPorts {
		args := []string{net.JoinHostPort(target, strconv.Itoa(port)), "--json_out", "-"}
		
		// Add StartTLS flags for specific ports
		if port == 389 {
			args = append(args, "--starttls=ldap")
		} else if port == 25 || port == 587 {
			args = append(args, "--starttls=smtp")
		} else if port == 143 {
			args = append(args, "--starttls=imap")
		} else if port == 110 {
			args = append(args, "--starttls=pop3")
		}

		raw, err := adapters.RunCLIScanner(ctx, binPath(a.Config), args, nil, "")
		if err != nil {
			fmt.Printf("[tlsscan] sslyze %s:%d failed: %v\n", target, port, err)
			continue
		}
		batch, err := scanSslyze(raw, asset.AssetID)
		if err != nil {
			fmt.Printf("[tlsscan] parse %s:%d failed: %v\n", target, port, err)
			continue
		}
		all.Findings = append(all.Findings, batch.Findings...)
	}

	return all, nil
}

// binPath returns the configured sslyze binary path.
func binPath(cfg Config) string {
	if cfg.BinPath != "" {
		return cfg.BinPath
	}
	return "sslyze"
}

// probeTLSPorts returns which of the given ports accept TCP connections,
// probing concurrently with a bounded worker pool.
func (a *Adapter) probeTLSPorts(ctx context.Context, target string, ports []int) []int {
	var (
		mu       sync.Mutex
		open     []int
		sem      = make(chan struct{}, 10)
		wg       sync.WaitGroup
	)
	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(p)), 3*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return open
}

// scanSslyze parses sslyze's structured JSON output into findings.
func scanSslyze(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output SslyzeOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}

	now := time.Now()
	var findings []models.Finding

	for _, scan := range output.ServerScanResults {
		host := scan.ServerLocation.Hostname
		r := scan.ScanResult

		if r.TLS10CipherSuites.Result.IsTLSVersionSupported {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: fmt.Sprintf("tls-v1.0-%s", host),
				Component:       "tls/1.0",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}
		if r.TLS11CipherSuites.Result.IsTLSVersionSupported {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: fmt.Sprintf("tls-v1.1-%s", host),
				Component:       "tls/1.1",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}
		for _, cs := range r.TLS12CipherSuites.Result.AcceptedCipherSuites {
			if cs.CipherSuite.IsAnonymous {
				findings = append(findings, models.Finding{
					AssetID:         assetID,
					SourceTool:      "tlsscan",
					VulnerabilityID: fmt.Sprintf("tls-anon-cipher-%s-%s", cs.CipherSuite.Name, host),
					Component:       "cipher/" + cs.CipherSuite.Name,
					Status:          "open",
					FirstSeen:       now,
					LastSeen:        now,
				})
			}
		}
		if r.TLSCompression.Result.SupportsCompression {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: fmt.Sprintf("tls-compression-%s", host),
				Component:       "tls/compression",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}
		if r.Hearbleed.Result.IsVulnerableToHeartbleed {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: "CVE-2014-0160",
				Component:       "openssl/heartbleed",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}
		if r.CCSInjection.Result.IsVulnerableToCCSInjection {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: "CVE-2014-0224",
				Component:       "openssl/ccs-injection",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}
		if r.SessionRenegotiation.Result.IsVulnerableToClientRenegotiationDoS {
			findings = append(findings, models.Finding{
				AssetID:         assetID,
				SourceTool:      "tlsscan",
				VulnerabilityID: "CVE-2011-1473",
				Component:       "tls/client-renegotiation",
				Status:          "open",
				FirstSeen:       now,
				LastSeen:        now,
			})
		}

		// Certificate validity: flag expired TLS certificates.
		for _, dep := range r.CertificateInfo.Result.CertificateDeployments {
			if len(dep.ReceivedCertificateChain) == 0 {
				continue
			}
			leaf := dep.ReceivedCertificateChain[0]
			if leaf.NotValidAfter == "" {
				continue
			}
			expiry, err := time.Parse(time.RFC3339, leaf.NotValidAfter)
			if err != nil {
				continue
			}
			if time.Now().After(expiry) {
				findings = append(findings, models.Finding{
					AssetID:         assetID,
					SourceTool:      "tlsscan",
					VulnerabilityID: fmt.Sprintf("tls-cert-expired-%s", host),
					Component:       "tls/certificate",
					Status:          "open",
					FirstSeen:       now,
					LastSeen:        now,
				})
			}
		}
	}

	return models.FindingsBatch{Findings: findings}, nil
}
