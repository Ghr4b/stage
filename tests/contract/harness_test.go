package contract

import (
	"context"
	"testing"
	"tijeri/internal/assets"
	"tijeri/internal/models"
)

func TestIdentitySignalContract(t *testing.T) {
	var sig assets.IdentitySignal = &FakeIdentitySignal{SigType: "mac_address", Val: "00:11:22:33:44:55", Conf: 0.9}
	if sig.SignalType() != "mac_address" {
		t.Errorf("Expected mac_address, got %s", sig.SignalType())
	}
}

func TestAssetIdentityResolverContract(t *testing.T) {
	resolver := &FakeAssetIdentityResolver{}
	sig := &FakeIdentitySignal{SigType: "mac_address", Val: "00:11:22:33:44:55", Conf: 0.9}
	
	id, err := resolver.Resolve(context.Background(), sig)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if id == "" {
		t.Errorf("Expected valid asset ID, got empty")
	}

	resolver.ShouldFail = true
	_, err = resolver.Resolve(context.Background(), sig)
	if err == nil {
		t.Errorf("Expected failure, got none")
	}
}

func TestScannerAdapterContract(t *testing.T) {
	adapter := &FakeScannerAdapter{}
	asset := models.Asset{AssetID: "a-1"}
	
	if !adapter.Supports(asset) {
		t.Errorf("Expected support for asset")
	}

	batch, err := adapter.Scan(context.Background(), asset)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(batch.Findings) == 0 {
		t.Errorf("Expected findings, got none")
	}
	if adapter.Name() != "FakeScanner" {
		t.Errorf("Expected FakeScanner, got %s", adapter.Name())
	}

	adapter.ShouldFail = true
	_, err = adapter.Scan(context.Background(), asset)
	if err == nil {
		t.Errorf("Expected failure, got none")
	}
}

func TestTicketingAdapterContract(t *testing.T) {
	adapter := &FakeTicketingAdapter{}
	finding := models.Finding{FindingID: "f-1"}
	
	id, err := adapter.CreateTicket(context.Background(), finding)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if id == "" {
		t.Errorf("Expected ticket ID, got empty")
	}

	err = adapter.UpdateTicket(context.Background(), id, models.TicketUpdate{Status: "in-progress"})
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	err = adapter.CloseTicket(context.Background(), id, "resolved")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if adapter.Name() != "FakeTicketing" {
		t.Errorf("Expected FakeTicketing, got %s", adapter.Name())
	}

	adapter.ShouldFail = true
	_, err = adapter.CreateTicket(context.Background(), finding)
	if err == nil {
		t.Errorf("Expected failure, got none")
	}
}
