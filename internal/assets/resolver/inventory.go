package resolver

import (
	"time"
)

// SoftwarePackage represents a single software component found on an asset.
type SoftwarePackage struct {
	Name    string
	Version string
}

// InventoryReport represents a list of packages reported by a specific source at a specific time.
type InventoryReport struct {
	Source    string
	Timestamp time.Time
	Packages  []SoftwarePackage
}

// InventoryState maintains the merged state of an asset's software inventory.
type InventoryState struct {
	// Map of package name to the most recent version and its reporting source metadata
	packages map[string]packageRecord
}

type packageRecord struct {
	Version   string
	Source    string
	Timestamp time.Time
}

func NewInventoryState() *InventoryState {
	return &InventoryState{
		packages: make(map[string]packageRecord),
	}
}

// MergeReport ingests a new inventory report.
// Latest-reporting-channel wins per package.
func (s *InventoryState) MergeReport(report InventoryReport) {
	for _, pkg := range report.Packages {
		existing, found := s.packages[pkg.Name]
		if !found || report.Timestamp.After(existing.Timestamp) {
			s.packages[pkg.Name] = packageRecord{
				Version:   pkg.Version,
				Source:    report.Source,
				Timestamp: report.Timestamp,
			}
		}
	}
}

// GetPackages returns the merged list of software packages.
func (s *InventoryState) GetPackages() []SoftwarePackage {
	var result []SoftwarePackage
	for name, record := range s.packages {
		result = append(result, SoftwarePackage{
			Name:    name,
			Version: record.Version,
		})
	}
	return result
}

// GetRecord returns the detailed record for a specific package, mostly for testing.
func (s *InventoryState) GetRecord(name string) (string, string, time.Time, bool) {
	record, found := s.packages[name]
	if !found {
		return "", "", time.Time{}, false
	}
	return record.Version, record.Source, record.Timestamp, true
}
