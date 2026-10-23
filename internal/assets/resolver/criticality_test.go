package resolver

import (
	"testing"
)

func TestCriticalityClassification(t *testing.T) {
	testCases := []struct {
		name     string
		ctx      AssetContext
		wantTier CriticalityTier
	}{
		{
			name: "public-facing + payment data -> highest tier (Critical)",
			ctx: AssetContext{
				Exposure: ExposurePublic,
				Data:     DataPCI,
				Role:     RoleProduction,
			},
			wantTier: TierCritical,
		},
		{
			name: "internal dev sandbox -> lowest tier (Low)",
			ctx: AssetContext{
				Exposure: ExposureInternal,
				Data:     DataNone,
				Role:     RoleSandbox,
			},
			wantTier: TierLow,
		},
		{
			name: "internal production with PII -> High tier",
			ctx: AssetContext{
				Exposure: ExposureInternal,
				Data:     DataPII,
				Role:     RoleProduction,
			},
			wantTier: TierHigh,
		},
		{
			name: "public facing staging with public data -> Medium tier",
			ctx: AssetContext{
				Exposure: ExposurePublic,
				Data:     DataPublic,
				Role:     RoleStaging,
			},
			wantTier: TierMedium,
		},
		{
			name: "airgapped dev with internal data -> Low tier",
			ctx: AssetContext{
				Exposure: ExposureAirGapped,
				Data:     DataInternal,
				Role:     RoleDev,
			},
			wantTier: TierLow,
		},
		{
			name: "internal staging with PII -> Medium tier (fallback)",
			ctx: AssetContext{
				Exposure: ExposureInternal,
				Data:     DataPII,
				Role:     RoleStaging,
			},
			wantTier: TierMedium,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotTier := Classify(tc.ctx)
			if gotTier != tc.wantTier {
				t.Errorf("Classify(%+v) = %v, want %v", tc.ctx, gotTier, tc.wantTier)
			}
		})
	}
}
