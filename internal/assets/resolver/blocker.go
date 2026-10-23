package resolver

import (
	"tijeri/internal/assets"
)

// SubnetBlocker assigns signals to blocks based on their subnet/cloud-account/OS-family.
// In a real implementation this would parse IP ranges and cloud metadata.
// For now, it uses the signal's Value as a simple blocking key.
type SubnetBlocker struct{}

func (b *SubnetBlocker) Block(signal assets.IdentitySignal) BlockKey {
	// Strategy: group by signal type as a coarse block.
	// In production this would be more sophisticated (e.g. /24 subnet, cloud account ID, OS family).
	return BlockKey(signal.SignalType())
}
