package email

import (
	"fmt"
	"html"
	"net/mail"
	"strings"
)

const accountCreatedSubject = "Your Identrail account is ready"

// AccountCreatedInput contains the personalized fields for a new-account email.
type AccountCreatedInput struct {
	From           string
	ReplyTo        string
	To             string
	DisplayName    string
	ContinueURL    string
	IdempotencyKey string
}

// AccountCreatedMessage renders the account-created transactional email.
func AccountCreatedMessage(input AccountCreatedInput) (Message, error) {
	to := strings.TrimSpace(input.To)
	if _, err := mail.ParseAddress(to); err != nil {
		return Message{}, fmt.Errorf("validate account-created recipient: %w", err)
	}
	from := strings.TrimSpace(input.From)
	if _, err := mail.ParseAddress(from); err != nil {
		return Message{}, fmt.Errorf("validate account-created sender: %w", err)
	}
	replyTo := strings.TrimSpace(input.ReplyTo)
	if replyTo != "" {
		if _, err := mail.ParseAddress(replyTo); err != nil {
			return Message{}, fmt.Errorf("validate account-created reply-to: %w", err)
		}
	}

	greeting := "Hi,"
	if name := accountFirstName(input.DisplayName); name != "" {
		greeting = "Hi " + name + ","
	}
	continueURL := strings.TrimSpace(input.ContinueURL)
	return Message{
		From:           from,
		To:             []string{to},
		ReplyTo:        replyTo,
		Subject:        accountCreatedSubject,
		Text:           accountCreatedText(greeting, continueURL),
		HTML:           accountCreatedHTML(greeting, continueURL),
		IdempotencyKey: firstNonEmptyHeader(input.IdempotencyKey, "account-created-"+safeHeaderValue(to)),
	}, nil
}

func firstNonEmptyHeader(values ...string) string {
	for _, value := range values {
		if trimmed := safeHeaderValue(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func accountFirstName(displayName string) string {
	name := strings.TrimSpace(displayName)
	if name == "" || strings.Contains(name, "@") {
		return ""
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return ""
	}
	first := strings.Trim(fields[0], ",")
	if first == "" || len([]rune(first)) > 40 {
		return ""
	}
	return first
}

func accountCreatedText(greeting string, continueURL string) string {
	parts := []string{
		greeting,
		"",
		"Your Identrail account is ready.",
		"",
		"You can now continue setting up your workspace, connect your first source, and start building a read-only view of your machine identity trust paths.",
	}
	if continueURL != "" {
		parts = append(parts, "", "Continue setup:", continueURL)
	} else {
		parts = append(parts, "", "Sign in to Identrail to continue your setup.")
	}
	parts = append(parts,
		"",
		"A quick note: Identrail will not ask for production credentials during onboarding. Source connections should stay read-only and scoped to what you choose to review.",
		"",
		"If you did not create this account, reply to this email and we will help secure it.",
		"",
		"Welcome,",
		"The Identrail team",
	)
	return strings.Join(parts, "\n")
}

func accountCreatedHTML(greeting string, continueURL string) string {
	escapedGreeting := html.EscapeString(greeting)
	cta := `<p style="margin:24px 0 0;color:#3f4654;font-size:15px;line-height:1.6;">Sign in to Identrail to continue your setup.</p>`
	if continueURL != "" {
		escapedURL := html.EscapeString(continueURL)
		cta = fmt.Sprintf(`<p style="margin:28px 0;"><a href="%s" style="display:inline-block;background:#10151f;color:#ffffff;text-decoration:none;border-radius:8px;padding:13px 18px;font-weight:700;">Continue setup</a></p><p style="margin:0;color:#6b7280;font-size:12px;line-height:1.5;">If the button does not work, open this link: <a href="%s" style="color:#4f46e5;">%s</a></p>`, escapedURL, escapedURL, escapedURL)
	}
	return fmt.Sprintf(`<!doctype html>
<html>
  <body style="margin:0;background:#f6f7fb;font-family:Arial,Helvetica,sans-serif;color:#10151f;">
    <div style="display:none;max-height:0;overflow:hidden;">Your Identrail account is ready.</div>
    <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="background:#f6f7fb;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border:1px solid #e5e7eb;border-radius:16px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px 8px;">
                <p style="margin:0 0 20px;color:#5b35e5;font-size:12px;font-weight:800;letter-spacing:0.08em;text-transform:uppercase;">Identrail</p>
                <h1 style="margin:0;color:#10151f;font-size:28px;line-height:1.15;">Your account is ready</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:8px 32px 32px;">
                <p style="margin:0 0 18px;color:#1f2937;font-size:16px;line-height:1.6;">%s</p>
                <p style="margin:0;color:#3f4654;font-size:15px;line-height:1.6;">You can now continue setting up your workspace, connect your first source, and start building a read-only view of your machine identity trust paths.</p>
                %s
                <div style="margin:28px 0 0;padding:16px 18px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:12px;">
                  <p style="margin:0;color:#3f4654;font-size:14px;line-height:1.6;"><strong>Security note:</strong> Identrail will not ask for production credentials during onboarding. Source connections should stay read-only and scoped to what you choose to review.</p>
                </div>
                <p style="margin:24px 0 0;color:#6b7280;font-size:13px;line-height:1.6;">If you did not create this account, reply to this email and we will help secure it.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`, escapedGreeting, cta)
}
