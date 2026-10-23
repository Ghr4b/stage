package cloud

import (
	"context"
	"testing"
)

type MockCloudAdapter struct {
	SyncCalled         bool
	QueryCalled        bool
	ProcessEventCalled bool
	QueryResult        []map[string]interface{}
}

func (m *MockCloudAdapter) Sync(ctx context.Context) error {
	m.SyncCalled = true
	return nil
}

func (m *MockCloudAdapter) Query(ctx context.Context, query string) ([]map[string]interface{}, error) {
	m.QueryCalled = true
	return m.QueryResult, nil
}

func (m *MockCloudAdapter) ProcessEvent(ctx context.Context, eventPayload []byte) error {
	m.ProcessEventCalled = true
	return nil
}

func TestAdapterInterfaceSwap(t *testing.T) {
	// Function that takes the interface and uses it (representing the call site)
	runSyncJob := func(adapter CloudDiscoveryAdapter) {
		_ = adapter.Sync(context.Background())
		_ = adapter.ProcessEvent(context.Background(), []byte(`{"event":"test"}`))
	}

	mockAdapter := &MockCloudAdapter{}
	runSyncJob(mockAdapter)

	if !mockAdapter.SyncCalled {
		t.Error("Expected Sync to be called on mock adapter")
	}
	if !mockAdapter.ProcessEventCalled {
		t.Error("Expected ProcessEvent to be called on mock adapter")
	}
	
	// Test query independently
	mockAdapter.QueryResult = []map[string]interface{}{{"id": "test-id"}}
	res, err := mockAdapter.Query(context.Background(), "SELECT * FROM aws_ec2_instance")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(res) == 0 || res[0]["id"] != "test-id" {
		t.Error("Mock query did not return expected results")
	}
	if !mockAdapter.QueryCalled {
		t.Error("Expected Query to be called on mock adapter")
	}
}
