package urlpolicy

import "testing"

func TestValidateAuditForwardURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "https allowed", rawURL: "https://audit.example.com", wantErr: false},
		{name: "localhost http allowed", rawURL: "http://localhost:8081/audit", wantErr: false},
		{name: "loopback ipv4 http allowed", rawURL: "http://127.0.0.1:8081/audit", wantErr: false},
		{name: "loopback ipv6 http allowed", rawURL: "http://[::1]:8081/audit", wantErr: false},
		{name: "remote http denied", rawURL: "http://example.com/audit", wantErr: true},
		{name: "unsupported scheme denied", rawURL: "ftp://example.com/audit", wantErr: true},
		{name: "invalid url denied", rawURL: "://bad", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuditForwardURL(tt.rawURL)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.rawURL)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.rawURL, err)
			}
		})
	}
}
