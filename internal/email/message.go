package email

import "context"

// Message is the provider-neutral transactional email payload used by the API.
type Message struct {
	From           string
	To             []string
	ReplyTo        string
	Subject        string
	Text           string
	HTML           string
	IdempotencyKey string
}

// Sender sends one transactional email.
type Sender interface {
	Send(ctx context.Context, message Message) error
}
