package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"tijeri/internal/models"
)

// GenerateDedupHash computes the hash(asset_id + vulnerability_id + component).
func GenerateDedupHash(f models.Finding) string {
	data := fmt.Sprintf("%s|%s|%s", f.AssetID, f.VulnerabilityID, f.Component)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// DedupFindings collapses multiple findings with the same dedup_hash into one,
// combining their SourceTool values.
func DedupFindings(findings []models.Finding) []models.Finding {
	dedupMap := make(map[string]*models.Finding)
	
	for _, f := range findings {
		f.DedupHash = GenerateDedupHash(f)
		
		existing, ok := dedupMap[f.DedupHash]
		if !ok {
			// Copy finding and put into map
			newF := f
			dedupMap[f.DedupHash] = &newF
		} else {
			// Merge SourceTools
			tools := strings.Split(existing.SourceTool, ",")
			newTools := strings.Split(f.SourceTool, ",")
			
			toolSet := make(map[string]bool)
			for _, t := range tools {
				if t != "" { toolSet[strings.TrimSpace(t)] = true }
			}
			for _, t := range newTools {
				if t != "" { toolSet[strings.TrimSpace(t)] = true }
			}
			
			var uniqueTools []string
			for t := range toolSet {
				uniqueTools = append(uniqueTools, t)
			}
			sort.Strings(uniqueTools) // Keep consistent order
			
			existing.SourceTool = strings.Join(uniqueTools, ",")
		}
	}
	
	var result []models.Finding
	for _, f := range dedupMap {
		result = append(result, *f)
	}
	
	// Sort by FindingID for consistent output
	sort.Slice(result, func(i, j int) bool {
		return result[i].FindingID < result[j].FindingID
	})
	
	return result
}
