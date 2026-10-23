package adapters

import (
	"context"
	"tijeri/internal/models"
)

type ScannerAdapter interface {
	Supports(asset models.Asset) bool
	Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error)
	Name() string
}
