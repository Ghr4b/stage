package resolver

// CriticalityTier represents the importance/risk level of an asset.
type CriticalityTier string

const (
	TierCritical CriticalityTier = "Critical"
	TierHigh     CriticalityTier = "High"
	TierMedium   CriticalityTier = "Medium"
	TierLow      CriticalityTier = "Low"
)

// Exposure defines how an asset is accessible.
type Exposure string

const (
	ExposurePublic   Exposure = "public"
	ExposureInternal Exposure = "internal"
	ExposureAirGapped Exposure = "airgapped"
)

// DataClassification defines the sensitivity of data on the asset.
type DataClassification string

const (
	DataPCI      DataClassification = "pci"
	DataPII      DataClassification = "pii"
	DataInternal DataClassification = "internal"
	DataPublic   DataClassification = "public"
	DataNone     DataClassification = "none"
)

// Role defines the primary function of the asset.
type Role string

const (
	RoleProduction Role = "production"
	RoleStaging    Role = "staging"
	RoleDev        Role = "dev"
	RoleSandbox    Role = "sandbox"
)

// AssetContext contains the metadata needed to calculate criticality.
type AssetContext struct {
	Exposure Exposure
	Data     DataClassification
	Role     Role
}

// Classify calculates the overall criticality tier based on exposure, data, and role.
func Classify(ctx AssetContext) CriticalityTier {
	// Highest risk: public-facing with sensitive data
	if ctx.Exposure == ExposurePublic && (ctx.Data == DataPCI || ctx.Data == DataPII) {
		return TierCritical
	}

	// High risk: production with sensitive data, OR public-facing production
	if (ctx.Role == RoleProduction && (ctx.Data == DataPCI || ctx.Data == DataPII)) ||
		(ctx.Exposure == ExposurePublic && ctx.Role == RoleProduction) {
		return TierHigh
	}

	// Low risk: development/sandbox with no sensitive data
	if (ctx.Role == RoleDev || ctx.Role == RoleSandbox) &&
		(ctx.Data == DataPublic || ctx.Data == DataNone || ctx.Data == DataInternal) &&
		(ctx.Exposure == ExposureInternal || ctx.Exposure == ExposureAirGapped) {
		return TierLow
	}

	// Default/Mid-tier for everything else
	return TierMedium
}
