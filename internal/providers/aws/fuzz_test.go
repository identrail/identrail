package aws

import "testing"

// FuzzParsePolicyDocument exercises IAM policy/trust-document parsing, which
// URL-unescapes and JSON-decodes untrusted document strings collected from AWS.
// Parsing must always return cleanly (document or error) and never panic.
func FuzzParsePolicyDocument(f *testing.F) {
	seeds := []string{
		`{"Version":"2012-10-17","Statement":[]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`,
		"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D",
		`{"Statement":"not-an-array"}`,
		`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`,
		"not json",
		"%zz",
		"%",
		"   ",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, raw string) {
		// Result is intentionally ignored: the contract under test is that the
		// parser never panics on arbitrary, possibly URL-encoded input.
		_, _ = parsePolicyDocument(raw)
	})
}
