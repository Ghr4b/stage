package normalize

import (
	"testing"
	"tijeri/internal/models"
)

func TestCVSSVersionHandling(t *testing.T) {
	v3 := models.CVSS{Version: "3.1", Score: 7.5}
	v4 := models.CVSS{Version: "4.0", Score: 8.0}
	v3b := models.CVSS{Version: "3.1", Score: 9.0}

	t.Run("Cross-version comparison fails loudly", func(t *testing.T) {
		_, err := CompareCVSS(v3, v4)
		if err == nil {
			t.Error("Expected error when comparing CVSS 3.1 and 4.0")
		}
	})

	t.Run("Same-version comparison passes", func(t *testing.T) {
		res, err := CompareCVSS(v3, v3b)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if res != -1 {
			t.Errorf("Expected -1 since 7.5 < 9.0, got %d", res)
		}
	})
}
