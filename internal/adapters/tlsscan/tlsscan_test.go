package tlsscan

import (
	"tijeri/internal/models"
	"testing"
)

func TestAdapter(t *testing.T) {
	adapter := &Adapter{}
	if adapter.Name() != "tlsscan" {
		t.Errorf("Expected tlsscan, got %s", adapter.Name())
	}
	if !adapter.Supports(models.Asset{Type: "host"}) {
		t.Errorf("Expected host to be supported")
	}
	if adapter.Supports(models.Asset{Type: "container"}) {
		t.Errorf("Expected container to not be supported")
	}
}

func TestScanSslyze(t *testing.T) {
	raw := []byte(`{
		"invalid_server_strings": [],
		"server_scan_results": [
			{
				"server_location": {"hostname": "2026.1.1.1", "port": 443},
				"scan_result": {
					"tls_1_0_cipher_suites": {
						"status": "COMPLETED",
						"result": {"tls_version_used": "TLS_1_0", "is_tls_version_supported": true, "accepted_cipher_suites": []}
					},
					"tls_1_1_cipher_suites": {
						"status": "COMPLETED",
						"result": {"tls_version_used": "TLS_1_1", "is_tls_version_supported": false, "accepted_cipher_suites": []}
					},
					"tls_1_2_cipher_suites": {
						"status": "COMPLETED",
						"result": {"tls_version_used": "TLS_1_2", "is_tls_version_supported": true, "accepted_cipher_suites": [
							{"cipher_suite": {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "is_anonymous": false}},
							{"cipher_suite": {"name": "TLS_DH_anon_WITH_AES_128_CBC_SHA", "is_anonymous": true}}
						]}
					},
					"tls_compression": {"status": "COMPLETED", "result": {"supports_compression": true}},
					"heartbleed": {"status": "COMPLETED", "result": {"is_vulnerable_to_heartbleed": false}},
					"openssl_ccs_injection": {"status": "COMPLETED", "result": {"is_vulnerable_to_ccs_injection": false}},
					"session_renegotiation": {"status": "COMPLETED", "result": {"is_vulnerable_to_client_renegotiation_dos": false}},
					"certificate_info": {"status": "COMPLETED", "result": {"certificate_deployments": [
						{"received_certificate_chain": [
							{"not_valid_before": "2020-01-01T00:00:00Z", "not_valid_after": "2021-01-01T00:00:00Z"}
						]}
					]}}
				}
			}
		]
	}`)

	batch, err := scanSslyze(raw, "asset-123")
	if err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if len(batch.Findings) != 4 {
		t.Errorf("Expected 4 findings (TLS1.0, anon cipher, compression, expired cert), got %d", len(batch.Findings))
	}

	foundExpired := false
	for _, f := range batch.Findings {
		if f.VulnerabilityID == "tls-cert-expired-2026.1.1.1" {
			foundExpired = true
		}
	}
	if !foundExpired {
		t.Errorf("Expected expired-certificate finding, not found in: %+v", batch.Findings)
	}
}