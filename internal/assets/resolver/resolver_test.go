package resolver

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"tijeri/internal/assets"
)

// --- Test helpers ---

type spyCompareFunc struct {
	mu         sync.Mutex
	callPairs  [][2]string // records (a.Value(), b.Value()) for each call
	decision   MergeDecision
}

func (s *spyCompareFunc) Compare(a, b assets.IdentitySignal) MergeDecision {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callPairs = append(s.callPairs, [2]string{a.Value(), b.Value()})
	return s.decision
}

func (s *spyCompareFunc) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.callPairs)
}

func (s *spyCompareFunc) CalledWith(aVal, bVal string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, pair := range s.callPairs {
		if pair[0] == aVal && pair[1] == bVal {
			return true
		}
		if pair[0] == bVal && pair[1] == aVal {
			return true
		}
	}
	return false
}

type testSignal struct {
	sigType string
	value   string
	conf    float64
}

func (s *testSignal) SignalType() string  { return s.sigType }
func (s *testSignal) Value() string       { return s.value }
func (s *testSignal) Confidence() float64 { return s.conf }

// inMemoryStore is a simple in-memory store for testing.
type inMemoryStore struct {
	mu      sync.Mutex
	signals map[BlockKey][]StoredSignal
	nextID  int
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{signals: make(map[BlockKey][]StoredSignal)}
}

func (s *inMemoryStore) LookupByBlock(ctx context.Context, block BlockKey) ([]StoredSignal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signals[block], nil
}

func (s *inMemoryStore) StoreSignal(ctx context.Context, assetID string, signal assets.IdentitySignal, block BlockKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signals[block] = append(s.signals[block], StoredSignal{AssetID: assetID, Signal: signal})
	return nil
}

func (s *inMemoryStore) NextAssetID(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	return fmt.Sprintf("asset-%d", s.nextID), nil
}

// --- Unit Tests ---

// TestBlockingCrossBlockIsolation: Two signals in different blocks are NEVER compared.
func TestBlockingCrossBlockIsolation(t *testing.T) {
	spy := &spyCompareFunc{decision: MergeDecision{ShouldMerge: false}}
	store := newInMemoryStore()

	resolver := &Resolver{
		Blocker:     &SubnetBlocker{},
		CompareFunc: spy.Compare,
		Store:       store,
	}

	ctx := context.Background()

	// Signal A: type "ip" → block "ip"
	sigA := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}
	// Signal B: type "mac_address" → block "mac_address" (different block)
	sigB := &testSignal{sigType: "mac_address", value: "00:11:22:33:44:55", conf: 1.0}

	_, err := resolver.Resolve(ctx, sigA)
	if err != nil {
		t.Fatalf("Resolve(sigA) error: %v", err)
	}
	_, err = resolver.Resolve(ctx, sigB)
	if err != nil {
		t.Fatalf("Resolve(sigB) error: %v", err)
	}

	// The spy should have recorded zero cross-block comparison calls.
	// sigA is the only signal in the "ip" block when it's inserted (0 comparisons).
	// sigB is the only signal in the "mac_address" block when it's inserted (0 comparisons).
	if spy.CalledWith("10.0.0.1", "00:11:22:33:44:55") {
		t.Error("CRITICAL: Cross-block comparison occurred between signals in different blocks")
	}

	// Also verify total call count is 0 — neither signal had an existing peer in its block.
	if spy.CallCount() != 0 {
		t.Errorf("Expected 0 compare calls (each signal is alone in its block), got %d", spy.CallCount())
	}
}

// TestBlockingSameBlockCompared: Two signals in the SAME block ARE compared.
func TestBlockingSameBlockCompared(t *testing.T) {
	spy := &spyCompareFunc{decision: MergeDecision{ShouldMerge: false}}
	store := newInMemoryStore()

	resolver := &Resolver{
		Blocker:     &SubnetBlocker{},
		CompareFunc: spy.Compare,
		Store:       store,
	}

	ctx := context.Background()

	// Both signals share type "ip" → same block
	sigA := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}
	sigB := &testSignal{sigType: "ip", value: "10.0.0.2", conf: 1.0}

	_, err := resolver.Resolve(ctx, sigA)
	if err != nil {
		t.Fatalf("Resolve(sigA) error: %v", err)
	}
	_, err = resolver.Resolve(ctx, sigB)
	if err != nil {
		t.Fatalf("Resolve(sigB) error: %v", err)
	}

	// The spy should have exactly 1 comparison: sigB vs sigA (sigA was already stored when sigB arrived).
	if spy.CallCount() != 1 {
		t.Errorf("Expected 1 compare call (same block), got %d", spy.CallCount())
	}
	if !spy.CalledWith("10.0.0.2", "10.0.0.1") {
		t.Error("Expected comparison between 10.0.0.1 and 10.0.0.2")
	}
}

// TestBenchmarkComparisonCountScaling: Comparison count scales with block size, not total asset count.
func TestBenchmarkComparisonCountScaling(t *testing.T) {
	// Scenario: N=100 signals across K=10 equal blocks (10 signals per block).
	// Expected comparisons per block: 0+1+2+...+9 = 45
	// Total expected: 10 * 45 = 450
	// Without blocking (single block): 0+1+2+...+99 = 4950
	
	N := 100
	K := 10
	signalsPerBlock := N / K

	spy := &spyCompareFunc{decision: MergeDecision{ShouldMerge: false}}
	store := newInMemoryStore()

	// Custom blocker that assigns to K blocks deterministically.
	blocker := &fixedBlocker{k: K}

	resolver := &Resolver{
		Blocker:     blocker,
		CompareFunc: spy.Compare,
		Store:       store,
	}

	ctx := context.Background()

	for i := 0; i < N; i++ {
		sig := &testSignal{
			sigType: fmt.Sprintf("block-%d", i%K),
			value:   fmt.Sprintf("signal-%d", i),
			conf:    1.0,
		}
		_, err := resolver.Resolve(ctx, sig)
		if err != nil {
			t.Fatalf("Resolve signal-%d error: %v", i, err)
		}
	}

	// Expected comparisons: K * (signalsPerBlock*(signalsPerBlock-1)/2)
	expectedComparisons := K * (signalsPerBlock * (signalsPerBlock - 1) / 2)
	actualComparisons := spy.CallCount()

	if actualComparisons != expectedComparisons {
		t.Errorf("Expected %d comparisons (O(N²/K)), got %d", expectedComparisons, actualComparisons)
	}

	// Sanity: without blocking it would be N*(N-1)/2 = 4950
	withoutBlocking := N * (N - 1) / 2
	t.Logf("With blocking: %d comparisons (K=%d blocks). Without: %d. Ratio: %.2fx reduction",
		actualComparisons, K, withoutBlocking, float64(withoutBlocking)/float64(actualComparisons))
}

// fixedBlocker assigns signals to K blocks based on their signal type.
type fixedBlocker struct {
	k int
}

func (b *fixedBlocker) Block(signal assets.IdentitySignal) BlockKey {
	return BlockKey(signal.SignalType())
}
