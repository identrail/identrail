package telemetry

import "go.uber.org/zap"

// NewLogger returns a production-safe structured logger.
func NewLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
		cfg.Level.SetLevel(zap.InfoLevel)
	}
	return cfg.Build()
}

// ZapError centralizes error field formatting.
func ZapError(err error) zap.Field {
	return zap.Error(err)
}

// String aliases zap.String for cleaner call sites outside telemetry package.
func String(key, val string) zap.Field {
	return zap.String(key, val)
}

// StandardLogFields returns the baseline fields every structured operational log
// should carry so API, worker, and scanner logs remain easy to correlate.
func StandardLogFields(component string, operation string, fields ...zap.Field) []zap.Field {
	result := make([]zap.Field, 0, 2)
	result = append(result,
		zap.String("component", component),
		zap.String("operation", operation),
	)
	result = append(result, fields...)
	return result
}
