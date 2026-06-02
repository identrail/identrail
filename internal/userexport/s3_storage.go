package userexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3API is the subset of the AWS S3 client used by S3Storage.
type S3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3Storage persists bundles in S3 so API and worker tasks can share completed
// exports across process and host boundaries.
type S3Storage struct {
	Client S3API
	Bucket string
	Prefix string
}

// NewS3Storage returns a storage backend rooted at bucket/prefix.
func NewS3Storage(client S3API, bucket string, prefix string) (*S3Storage, error) {
	if client == nil {
		return nil, errors.New("userexport: s3 client is required")
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return nil, errors.New("userexport: s3 bucket is required")
	}
	return &S3Storage{
		Client: client,
		Bucket: bucket,
		Prefix: normalizeS3Prefix(prefix),
	}, nil
}

// Put writes a bundle to S3 and returns its object URI.
func (s *S3Storage) Put(ctx context.Context, key string, r io.Reader) (string, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return "", err
	}
	if r == nil {
		r = bytes.NewReader(nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	_, err = s.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.Bucket),
		Key:         aws.String(objectKey),
		Body:        r,
		ContentType: aws.String("application/zip"),
	})
	if err != nil {
		return "", fmt.Errorf("put export object: %w", err)
	}
	return "s3://" + s.Bucket + "/" + objectKey, nil
}

// Open returns a read handle for an existing S3 bundle.
func (s *S3Storage) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return nil, fmt.Errorf("open export object: %w", err)
	}
	return out.Body, nil
}

// Delete removes a bundle. S3 DeleteObject is idempotent for missing keys.
func (s *S3Storage) Delete(ctx context.Context, key string) error {
	objectKey, err := s.objectKey(key)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(objectKey),
	}); err != nil {
		return fmt.Errorf("delete export object: %w", err)
	}
	return nil
}

func (s *S3Storage) objectKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", errors.New("userexport: key is required")
	}
	if strings.Contains(key, "..") || strings.HasPrefix(key, "/") || strings.Contains(key, "\x00") {
		return "", fmt.Errorf("userexport: invalid key %q", key)
	}
	cleaned := path.Clean(key)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("userexport: invalid key %q", key)
	}
	return s.Prefix + cleaned, nil
}

func normalizeS3Prefix(prefix string) string {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix == "" {
		return ""
	}
	return path.Clean(prefix) + "/"
}
