package db

import (
	"strings"
	"testing"
	"time"
)

func TestPostgresPoolConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("IDENTRAIL_POSTGRES_MAX_OPEN_CONNS", "")
	t.Setenv("IDENTRAIL_POSTGRES_MAX_IDLE_CONNS", "")
	t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_LIFETIME", "")
	t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_IDLE_TIME", "")

	config, err := postgresPoolConfigFromEnv()
	if err != nil {
		t.Fatalf("postgresPoolConfigFromEnv: %v", err)
	}
	if config.maxOpenConns != 20 {
		t.Fatalf("expected max open conns 20, got %d", config.maxOpenConns)
	}
	if config.maxIdleConns != 5 {
		t.Fatalf("expected max idle conns 5, got %d", config.maxIdleConns)
	}
	if config.connMaxLifetime != 30*time.Minute {
		t.Fatalf("expected max lifetime 30m, got %s", config.connMaxLifetime)
	}
	if config.connMaxIdleTime != 5*time.Minute {
		t.Fatalf("expected max idle time 5m, got %s", config.connMaxIdleTime)
	}
}

func TestPostgresPoolConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("IDENTRAIL_POSTGRES_MAX_OPEN_CONNS", "4")
	t.Setenv("IDENTRAIL_POSTGRES_MAX_IDLE_CONNS", "0")
	t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_LIFETIME", "10m")
	t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_IDLE_TIME", "30s")

	config, err := postgresPoolConfigFromEnv()
	if err != nil {
		t.Fatalf("postgresPoolConfigFromEnv: %v", err)
	}
	if config.maxOpenConns != 4 {
		t.Fatalf("expected max open conns 4, got %d", config.maxOpenConns)
	}
	if config.maxIdleConns != 0 {
		t.Fatalf("expected max idle conns 0, got %d", config.maxIdleConns)
	}
	if config.connMaxLifetime != 10*time.Minute {
		t.Fatalf("expected max lifetime 10m, got %s", config.connMaxLifetime)
	}
	if config.connMaxIdleTime != 30*time.Second {
		t.Fatalf("expected max idle time 30s, got %s", config.connMaxIdleTime)
	}
}

func TestPostgresPoolConfigFromEnvRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		value   string
		want    string
	}{
		{
			name:    "non integer max open conns",
			envName: "IDENTRAIL_POSTGRES_MAX_OPEN_CONNS",
			value:   "many",
			want:    "IDENTRAIL_POSTGRES_MAX_OPEN_CONNS must be an integer",
		},
		{
			name:    "negative max idle conns",
			envName: "IDENTRAIL_POSTGRES_MAX_IDLE_CONNS",
			value:   "-1",
			want:    "IDENTRAIL_POSTGRES_MAX_IDLE_CONNS must be >= 0",
		},
		{
			name:    "invalid lifetime",
			envName: "IDENTRAIL_POSTGRES_CONN_MAX_LIFETIME",
			value:   "later",
			want:    "IDENTRAIL_POSTGRES_CONN_MAX_LIFETIME must be a Go duration",
		},
		{
			name:    "negative idle time",
			envName: "IDENTRAIL_POSTGRES_CONN_MAX_IDLE_TIME",
			value:   "-1s",
			want:    "IDENTRAIL_POSTGRES_CONN_MAX_IDLE_TIME must be >= 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("IDENTRAIL_POSTGRES_MAX_OPEN_CONNS", "")
			t.Setenv("IDENTRAIL_POSTGRES_MAX_IDLE_CONNS", "")
			t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_LIFETIME", "")
			t.Setenv("IDENTRAIL_POSTGRES_CONN_MAX_IDLE_TIME", "")
			t.Setenv(tc.envName, tc.value)

			_, err := postgresPoolConfigFromEnv()
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %q", tc.want, err.Error())
			}
		})
	}
}
