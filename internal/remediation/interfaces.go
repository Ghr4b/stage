package remediation

import (
	"context"
	"tijeri/internal/models"
)

type TicketingAdapter interface {
	CreateTicket(ctx context.Context, f models.Finding) (ticketID string, err error)
	UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error
	CloseTicket(ctx context.Context, ticketID string, reason string) error
	Name() string
}
