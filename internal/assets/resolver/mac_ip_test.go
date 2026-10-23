package resolver

import (
	"testing"
	"time"
)

func TestMACNotInDeterministicTier(t *testing.T) {
	// Three signals bearing three different randomized MACs for what fixture
	// metadata says is one physical device must NOT auto-merge on MAC alone.
	macs := []string{"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:03"}

	for _, mac := range macs {
		a := &testSignal{sigType: "mac_address", value: mac, conf: 1.0}
		b := &testSignal{sigType: "mac_address", value: macs[0], conf: 1.0}

		decision := DeterministicCompare(a, b)
		if decision.ShouldMerge {
			t.Errorf("INVARIANT I2 VIOLATION: MAC-based signal auto-merged in deterministic tier! MAC=%s", mac)
		}
	}
}

func TestIPNotInDeterministicTier(t *testing.T) {
	a := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}
	b := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}

	decision := DeterministicCompare(a, b)
	if decision.ShouldMerge {
		t.Error("INVARIANT I2 VIOLATION: IP-based signal auto-merged in deterministic tier!")
	}
}

func TestIsMACOrIP(t *testing.T) {
	if !IsMACOrIP("mac_address") {
		t.Error("Expected mac_address to be recognized as MAC/IP")
	}
	if !IsMACOrIP("ip") {
		t.Error("Expected ip to be recognized as MAC/IP")
	}
	if IsMACOrIP("cloud_instance_id") {
		t.Error("cloud_instance_id should not be MAC/IP")
	}
}

func TestIPConfidenceDecayMonotonicallyDecreasing(t *testing.T) {
	baseConf := 0.9

	prevConf := baseConf
	for days := 0; days <= 90; days += 5 {
		delta := time.Duration(days) * 24 * time.Hour
		conf := ConfidenceDecay(baseConf, delta)

		if days > 0 && conf >= prevConf {
			t.Errorf("Confidence NOT monotonically decreasing: day %d (%.4f) >= day %d (%.4f)",
				days, conf, days-5, prevConf)
		}

		prevConf = conf
	}

	// At t+30 days, confidence must be strictly lower than at t+0
	conf0 := ConfidenceDecay(baseConf, 0)
	conf30 := ConfidenceDecay(baseConf, 30*24*time.Hour)
	if conf30 >= conf0 {
		t.Errorf("Confidence at t+30d (%.4f) is NOT lower than at t+0 (%.4f)", conf30, conf0)
	}

	t.Logf("Decay curve: t=0: %.4f, t=15d: %.4f, t=30d: %.4f, t=60d: %.4f, t=90d: %.4f",
		ConfidenceDecay(baseConf, 0),
		ConfidenceDecay(baseConf, 15*24*time.Hour),
		ConfidenceDecay(baseConf, 30*24*time.Hour),
		ConfidenceDecay(baseConf, 60*24*time.Hour),
		ConfidenceDecay(baseConf, 90*24*time.Hour))
}
