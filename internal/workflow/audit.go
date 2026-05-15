package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// JSONLineAuditSink writes one DispatchRecord per line as NDJSON to the
// configured writer. Suitable for governance-friendly append-only audit logs
// and easy ingestion by SIEM pipelines.
type JSONLineAuditSink struct {
	Writer io.Writer

	mu sync.Mutex
}

// Record implements AuditSink by serializing the record as one JSON line.
func (s *JSONLineAuditSink) Record(_ context.Context, record DispatchRecord) error {
	if s.Writer == nil {
		return fmt.Errorf("audit sink writer is nil")
	}
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.Writer.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}
