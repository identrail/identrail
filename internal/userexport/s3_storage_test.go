package userexport_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/identrail/identrail/internal/userexport"
)

type fakeS3Client struct {
	putBucket    string
	putKey       string
	putBody      string
	getBucket    string
	getKey       string
	deleteBucket string
	deleteKey    string
}

func (f *fakeS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.putBucket = *input.Bucket
	f.putKey = *input.Key
	if input.Body != nil {
		body, err := io.ReadAll(input.Body)
		if err != nil {
			return nil, err
		}
		f.putBody = string(body)
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.getBucket = *input.Bucket
	f.getKey = *input.Key
	return &s3.GetObjectOutput{Body: io.NopCloser(strings.NewReader("bundle"))}, nil
}

func (f *fakeS3Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deleteBucket = *input.Bucket
	f.deleteKey = *input.Key
	return &s3.DeleteObjectOutput{}, nil
}

func TestS3StorageRejectsInvalidInputs(t *testing.T) {
	if _, err := userexport.NewS3Storage(nil, "bucket", "prefix"); err == nil {
		t.Fatal("expected missing client error")
	}
	storage, err := userexport.NewS3Storage(&fakeS3Client{}, "  ", "prefix")
	if err == nil || storage != nil {
		t.Fatal("expected blank bucket error")
	}
	storage, err = userexport.NewS3Storage(&fakeS3Client{}, "exports", "prefix")
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	for _, key := range []string{"", " ../escape.zip ", "/absolute.zip", "nested/../escape.zip", "bad\x00key.zip"} {
		if _, err := storage.Put(context.Background(), key, strings.NewReader("data")); err == nil {
			t.Fatalf("expected Put to reject key %q", key)
		}
		if _, err := storage.Open(context.Background(), key); err == nil {
			t.Fatalf("expected Open to reject key %q", key)
		}
		if err := storage.Delete(context.Background(), key); err == nil {
			t.Fatalf("expected Delete to reject key %q", key)
		}
	}
}

func TestS3StorageRoundTrip(t *testing.T) {
	client := &fakeS3Client{}
	storage, err := userexport.NewS3Storage(client, "exports", "/tenant-data/")
	if err != nil {
		t.Fatalf("storage: %v", err)
	}
	location, err := storage.Put(context.Background(), "user/job.zip", strings.NewReader("bundle"))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if location != "s3://exports/tenant-data/user/job.zip" {
		t.Fatalf("unexpected location %q", location)
	}
	if client.putBucket != "exports" || client.putKey != "tenant-data/user/job.zip" || client.putBody != "bundle" {
		t.Fatalf("unexpected put bucket=%q key=%q body=%q", client.putBucket, client.putKey, client.putBody)
	}

	rc, err := storage.Open(context.Background(), "user/job.zip")
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
	if client.getBucket != "exports" || client.getKey != "tenant-data/user/job.zip" {
		t.Fatalf("unexpected get bucket=%q key=%q", client.getBucket, client.getKey)
	}

	if err := storage.Delete(context.Background(), "user/job.zip"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if client.deleteBucket != "exports" || client.deleteKey != "tenant-data/user/job.zip" {
		t.Fatalf("unexpected delete bucket=%q key=%q", client.deleteBucket, client.deleteKey)
	}
}
