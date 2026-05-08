package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditFingerprintSecretIsDocumented(t *testing.T) {
	required := "IDENTRAIL_AUDIT_FINGERPRINT_SECRET"
	for _, relPath := range []string{
		filepath.Join("docs", "configuration-reference.md"),
		filepath.Join("docs", "phase-2.md"),
	} {
		content := readRepositoryFile(t, relPath)
		if !strings.Contains(content, required) {
			t.Fatalf("%s must document %s", relPath, required)
		}
	}
}

func readRepositoryFile(t *testing.T, relPath string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	path := filepath.Join(root, relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	return string(data)
}
