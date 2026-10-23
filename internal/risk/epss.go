package risk

import (
	"sort"
)

type ScoredFinding struct {
	ID        string
	BODTier   int     // deadline tier from Step 1 (e.g., 3, 7, 14, 30, 90)
	EPSSScore float64 // intra-tier ranking
}

// RankFindings orders findings primarily by BODTier (ascending, smaller deadline = higher priority)
// and secondarily by EPSSScore (descending, higher score = higher priority).
// This enforces I9: EPSS only reorders findings *within* a BOD tier.
func RankFindings(findings []ScoredFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].BODTier != findings[j].BODTier {
			return findings[i].BODTier < findings[j].BODTier
		}
		return findings[i].EPSSScore > findings[j].EPSSScore
	})
}
