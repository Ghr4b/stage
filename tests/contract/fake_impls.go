package contract

import (
	"context"
	"errors"
	"tijeri/internal/adapters"
	"tijeri/internal/assets"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

var _ assets.IdentitySignal = (*FakeIdentitySignal)(nil)
var _ assets.AssetIdentityResolver = (*FakeAssetIdentityResolver)(nil)
var _ adapters.ScannerAdapter = (*FakeScannerAdapter)(nil)
var _ remediation.TicketingAdapter = (*FakeTicketingAdapter)(nil)

// FakeIdentitySignal
type FakeIdentitySignal struct {
	SigType string
	Val     string
	Conf    float64
}

func (f *FakeIdentitySignal) SignalType() string { return f.SigType }
func (f *FakeIdentitySignal) Value() string      { return f.Val }
func (f *FakeIdentitySignal) Confidence() float64 { return f.Conf }

// FakeAssetIdentityResolver
type FakeAssetIdentityResolver struct {
	ShouldFail bool
}

func (f *FakeAssetIdentityResolver) Resolve(ctx context.Context, signal assets.IdentitySignal) (string, error) {
	if f.ShouldFail {
		return "", errors.New("resolution failed")
	}
	return "asset-123", nil
}

// FakeScannerAdapter
type FakeScannerAdapter struct {
	ShouldFail bool
}

func (f *FakeScannerAdapter) Supports(asset models.Asset) bool {
	return true
}

func (f *FakeScannerAdapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	if f.ShouldFail {
		return models.FindingsBatch{}, errors.New("scan failed")
	}
	return models.FindingsBatch{Findings: []models.Finding{{FindingID: "f-123"}}}, nil
}

func (f *FakeScannerAdapter) Name() string { return "FakeScanner" }

// FakeTicketingAdapter
type FakeTicketingAdapter struct {
	ShouldFail bool
}

func (f *FakeTicketingAdapter) CreateTicket(ctx context.Context, finding models.Finding) (string, error) {
	if f.ShouldFail {
		return "", errors.New("create ticket failed")
	}
	return "ticket-123", nil
}

func (f *FakeTicketingAdapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	if f.ShouldFail {
		return errors.New("update ticket failed")
	}
	return nil
}

func (f *FakeTicketingAdapter) CloseTicket(ctx context.Context, ticketID string, reason string) error {
	if f.ShouldFail {
		return errors.New("close ticket failed")
	}
	return nil
}

func (f *FakeTicketingAdapter) Name() string { return "FakeTicketing" }
