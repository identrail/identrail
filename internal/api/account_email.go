package api

import (
	"context"
	"net/url"
	"strings"

	"github.com/identrail/identrail/internal/db"
	emailer "github.com/identrail/identrail/internal/email"
)

// SendAccountCreatedEmail sends the first-login account confirmation when email is configured.
func (s *Service) SendAccountCreatedEmail(ctx context.Context, user db.User, continueTo string) error {
	if s == nil || s.EmailSender == nil || strings.TrimSpace(s.EmailFromAddress) == "" {
		return nil
	}
	message, err := emailer.AccountCreatedMessage(emailer.AccountCreatedInput{
		From:        s.EmailFromAddress,
		ReplyTo:     s.EmailReplyToAddress,
		To:          user.PrimaryEmail,
		DisplayName: user.DisplayName,
		ContinueURL: s.accountCreatedContinueURL(continueTo),
	})
	if err != nil {
		return err
	}
	if trimmedID := strings.TrimSpace(user.ID); trimmedID != "" {
		message.IdempotencyKey = "account-created-" + sanitizeEmailIdempotencyComponent(trimmedID)
	}
	return s.EmailSender.Send(ctx, message)
}

func (s *Service) accountCreatedContinueURL(continueTo string) string {
	target := strings.TrimSpace(continueTo)
	if target == "" || target == "/" {
		target = "/onboarding/org"
	}
	if parsedTarget, err := url.Parse(target); err == nil && parsedTarget.IsAbs() {
		return target
	}
	base := strings.TrimRight(strings.TrimSpace(s.EmailAppBaseURL), "/")
	if base == "" {
		return ""
	}
	parsedBase, err := url.Parse(base)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" {
		return ""
	}
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return base + target
}

func sanitizeEmailIdempotencyComponent(raw string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, strings.TrimSpace(raw))
}
