package ml

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

// --- Mocks ---

type mockStore struct {
	feedback []models.AnalystFeedback
}

func (m *mockStore) SaveFinding(ctx context.Context, f models.Finding) error   { return nil }
func (m *mockStore) GetFinding(ctx context.Context, id string) (models.Finding, error) {
	return models.Finding{}, nil
}
func (m *mockStore) ListFindings(ctx context.Context, limit, offset int) ([]models.Finding, int, error) {
	return nil, 0, nil
}
func (m *mockStore) SaveAnalystFeedback(ctx context.Context, f models.AnalystFeedback) error {
	return nil
}
func (m *mockStore) GetAnalystFeedback(ctx context.Context) ([]models.AnalystFeedback, error) {
	return m.feedback, nil
}
func (m *mockStore) SaveAsset(ctx context.Context, a models.Asset) error { return nil }
func (m *mockStore) GetAsset(ctx context.Context, id string) (models.Asset, error) {
	return models.Asset{}, nil
}
func (m *mockStore) ListAssets(ctx context.Context, limit, offset int) ([]models.Asset, int, error) {
	return nil, 0, nil
}
func (m *mockStore) GetVulnerableHosts(ctx context.Context) ([]string, error) { return nil, nil }
func (m *mockStore) GetTicketHistory(ctx context.Context) ([]remediation.TicketHistory, error) {
	return nil, nil
}
func (m *mockStore) Migrate(migrationsDir string) error { return nil }
func (m *mockStore) Close() error                       { return nil }

type mockSubscriber struct {
	handlers map[string]func(msg []byte)
}

func newMockSubscriber() *mockSubscriber {
	return &mockSubscriber{handlers: make(map[string]func(msg []byte))}
}

func (m *mockSubscriber) Subscribe(subject string, handler func(msg []byte)) error {
	m.handlers[subject] = handler
	return nil
}

func (m *mockSubscriber) Emit(subject string, data []byte) {
	if h, ok := m.handlers[subject]; ok {
		h(data)
	}
}

// --- Tests ---

func TestRetrainerThresholdNotReachedDoesNotTrigger(t *testing.T) {
	db := &mockStore{}
	sub := newMockSubscriber()

	r := NewRetrainer(db, sub, 5, "/tmp/nonexistent-ml-dir")

	var triggered int32
	r.onTriggered = func() {
		atomic.AddInt32(&triggered, 1)
	}

	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Send 4 events (below threshold of 5)
	for i := 0; i < 4; i++ {
		sub.Emit("vamp.risk.feedback_recorded", []byte(`{"feedback_id":"fb-1"}`))
	}

	time.Sleep(50 * time.Millisecond) // let any goroutines settle

	if atomic.LoadInt32(&triggered) != 0 {
		t.Errorf("Expected 0 triggers below threshold, got %d", atomic.LoadInt32(&triggered))
	}
}

func TestRetrainerThresholdReachedTriggers(t *testing.T) {
	db := &mockStore{}
	sub := newMockSubscriber()

	r := NewRetrainer(db, sub, 3, "/tmp/nonexistent-ml-dir")

	var triggered int32
	var wg sync.WaitGroup
	wg.Add(1)
	r.onTriggered = func() {
		atomic.AddInt32(&triggered, 1)
		wg.Done()
	}

	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Send exactly 3 events (equals threshold)
	for i := 0; i < 3; i++ {
		sub.Emit("vamp.risk.feedback_recorded", []byte(`{"feedback_id":"fb-1"}`))
	}

	wg.Wait()

	if atomic.LoadInt32(&triggered) != 1 {
		t.Errorf("Expected exactly 1 trigger at threshold, got %d", atomic.LoadInt32(&triggered))
	}
}

func TestRetrainerCounterResetsAfterThreshold(t *testing.T) {
	db := &mockStore{}
	sub := newMockSubscriber()

	r := NewRetrainer(db, sub, 2, "/tmp/nonexistent-ml-dir")

	var triggered int32
	var wg sync.WaitGroup
	wg.Add(2) // expect 2 triggers total
	r.onTriggered = func() {
		atomic.AddInt32(&triggered, 1)
		wg.Done()
	}

	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Send 4 events — should trigger twice (at 2 and at 4)
	for i := 0; i < 4; i++ {
		sub.Emit("vamp.risk.feedback_recorded", []byte(`{"feedback_id":"fb-1"}`))
	}

	wg.Wait()

	if atomic.LoadInt32(&triggered) != 2 {
		t.Errorf("Expected 2 triggers after counter reset, got %d", atomic.LoadInt32(&triggered))
	}
}

func TestRetrainerSubscribesToCorrectSubject(t *testing.T) {
	db := &mockStore{}
	sub := newMockSubscriber()

	r := NewRetrainer(db, sub, 100, "/tmp/nonexistent-ml-dir")

	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	if _, ok := sub.handlers["vamp.risk.feedback_recorded"]; !ok {
		t.Error("Retrainer did not subscribe to vamp.risk.feedback_recorded")
	}
}

func TestRetrainerFeedbackFetchedFromDB(t *testing.T) {
	feedback := []models.AnalystFeedback{
		{
			FeedbackID:    "fb-001",
			FindingID:     "f-123",
			AnalystID:     "defectdojo-system",
			FeedbackType:  "status_override",
			OverrideValue: "false_positive",
			RecordedAt:    time.Now(),
			Source:        "defectdojo",
		},
	}
	db := &mockStore{feedback: feedback}
	sub := newMockSubscriber()

	r := NewRetrainer(db, sub, 1, "/tmp/nonexistent-ml-dir")

	var triggered int32
	var wg sync.WaitGroup
	wg.Add(1)
	r.onTriggered = func() {
		atomic.AddInt32(&triggered, 1)
		wg.Done()
	}

	if err := r.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	sub.Emit("vamp.risk.feedback_recorded", []byte(`{"feedback_id":"fb-001"}`))
	wg.Wait()

	if atomic.LoadInt32(&triggered) != 1 {
		t.Errorf("Expected 1 trigger, got %d", atomic.LoadInt32(&triggered))
	}

	// Verify the DB was actually called correctly
	got, err := db.GetAnalystFeedback(context.Background())
	if err != nil {
		t.Fatalf("GetAnalystFeedback error: %v", err)
	}
	if len(got) != 1 || got[0].FeedbackID != "fb-001" {
		t.Errorf("Expected feedback fb-001, got %+v", got)
	}
}

func (m *mockStore) SaveAuditLog(ctx context.Context, action, actor, resource, details string) error { return nil }
func (m *mockStore) ListAuditLogs(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) { return nil, nil }
