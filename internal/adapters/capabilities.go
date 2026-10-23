package adapters

import (
	"os/exec"
	"sort"
)

type ScannerCapability struct {
	Scanner   string
	Available bool
	Missing   []string
}

var scannerExecutableOptions = map[string][]string{
	"trivy":         {"trivy"},
	"grype":         {"grype"},
	"syft":          {"syft"},
	"gitleaks":      {"gitleaks"},
	"npm audit":     {"npm"},
	"govulncheck":   {"govulncheck"},
	"cargo audit":   {"cargo-audit"},
	"bundler-audit": {"bundle-audit"},
	"uv audit":      {"uv"},
	"osv-scanner":   {"osv-scanner"},
	"nuclei":        {"nuclei"},
	"tlsscan":       {"sslyze"},
	"prowler":       {"prowler"},
	"greenbone":     {"gvm-cli", "omp"},
}

func InspectScannerCapabilities(scannerNames []string) []ScannerCapability {
	return inspectScannerCapabilities(scannerNames, exec.LookPath)
}

func inspectScannerCapabilities(scannerNames []string, lookPath func(string) (string, error)) []ScannerCapability {
	names := append([]string(nil), scannerNames...)
	sort.Strings(names)
	capabilities := make([]ScannerCapability, 0, len(names))
	for _, name := range names {
		options, known := scannerExecutableOptions[name]
		capability := ScannerCapability{Scanner: name}
		if !known {
			capability.Missing = []string{"dependency mapping"}
			capabilities = append(capabilities, capability)
			continue
		}
		for _, option := range options {
			if _, err := lookPath(option); err == nil {
				capability.Available = true
				break
			}
			capability.Missing = append(capability.Missing, option)
		}
		if capability.Available {
			capability.Missing = nil
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities
}
