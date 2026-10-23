package normalize

import (
	"errors"
	"tijeri/internal/models"
)

// CompareCVSS numerically compares two CVSS scores, throwing an error if versions mismatch (I6).
func CompareCVSS(a, b models.CVSS) (int, error) {
	if a.Version != b.Version {
		return 0, errors.New("I6 violation: cross-version CVSS comparison is prohibited")
	}
	if a.Score < b.Score {
		return -1, nil
	}
	if a.Score > b.Score {
		return 1, nil
	}
	return 0, nil
}
