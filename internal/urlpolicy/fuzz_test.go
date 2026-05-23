package urlpolicy

import "testing"

// FuzzValidateAuditForwardURL exercises the outbound audit-forward URL guard
// with arbitrary input. The validator must always return cleanly (allow or
// error) and never panic on untrusted, attacker-controlled URLs.
func FuzzValidateAuditForwardURL(f *testing.F) {
	seeds := []string{
		"https://example.com",
		"http://localhost:8080/ingest",
		"http://127.0.0.1",
		"http://[::1]",
		"http://evil.example.com",
		"ftp://example.com",
		"://nohost",
		"https://",
		"   https://example.com   ",
		"http://localhost@evil.example.com",
		"",
		"%",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, raw string) {
		// Result is intentionally ignored: the contract under test is that the
		// validator never panics regardless of input.
		_ = ValidateAuditForwardURL(raw)
	})
}
