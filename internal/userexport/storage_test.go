package userexport_test

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/identrail/identrail/internal/userexport"
)

func TestLocalDiskStorageRejectsInvalidInputs(t *testing.T) {
	if _, err := userexport.NewLocalDiskStorage("  "); err == nil {
		t.Fatal("expected blank base dir error")
	}
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	for _, key := range []string{"", " ../escape.zip ", "/absolute.zip", "nested/../escape.zip", "bad\x00key.zip"} {
		if _, err := storage.Put(key, strings.NewReader("data")); err == nil {
			t.Fatalf("expected Put to reject key %q", key)
		}
		if _, err := storage.Open(key); err == nil {
			t.Fatalf("expected Open to reject key %q", key)
		}
		if err := storage.Delete(key); err == nil {
			t.Fatalf("expected Delete to reject key %q", key)
		}
	}
}

func TestLocalDiskStorageRoundTripAndDeleteMissing(t *testing.T) {
	storage, err := userexport.NewLocalDiskStorage(filepath.Join(t.TempDir(), "exports"))
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	path, err := storage.Put("user/job.zip", strings.NewReader("bundle"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if !strings.HasSuffix(path, filepath.Join("user", "job.zip")) {
		t.Fatalf("unexpected storage path: %s", path)
	}
	rc, err := storage.Open("user/job.zip")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	body, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "bundle" {
		t.Fatalf("unexpected body %q", body)
	}
	if err := storage.Delete("user/job.zip"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := storage.Delete("user/job.zip"); err != nil {
		t.Fatalf("delete missing should be idempotent: %v", err)
	}
}
