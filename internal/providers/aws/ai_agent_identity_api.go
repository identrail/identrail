package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/identrail/identrail/internal/providers"
)

// CompositeAIAgentIdentityAPI lets multiple metadata-only agent identity
// adapters feed the same ai-agent collector without duplicating collector
// service names in the AWS scanner.
type CompositeAIAgentIdentityAPI struct {
	apis []AIAgentIdentityAPI
}

var _ AIAgentIdentityAPI = (*CompositeAIAgentIdentityAPI)(nil)

func NewCompositeAIAgentIdentityAPI(apis ...AIAgentIdentityAPI) AIAgentIdentityAPI {
	filtered := make([]AIAgentIdentityAPI, 0, len(apis))
	for _, api := range apis {
		if api != nil {
			filtered = append(filtered, api)
		}
	}
	return &CompositeAIAgentIdentityAPI{apis: filtered}
}

func (a *CompositeAIAgentIdentityAPI) ListAgentIdentities(ctx context.Context, nextToken string, pageSize int32) (AIAgentIdentityPage, error) {
	if a == nil || len(a.apis) == 0 {
		return AIAgentIdentityPage{}, nil
	}
	apiIndex, sourceToken, err := parseCompositeAIAgentIdentityToken(nextToken)
	if err != nil {
		return AIAgentIdentityPage{}, err
	}
	if apiIndex >= len(a.apis) {
		return AIAgentIdentityPage{}, fmt.Errorf("invalid ai agent identity pagination token")
	}
	diagnostics := []providers.SourceError{}
	for apiIndex < len(a.apis) {
		if err := ctx.Err(); err != nil {
			return AIAgentIdentityPage{}, err
		}
		page, err := a.apis[apiIndex].ListAgentIdentities(ctx, sourceToken, pageSize)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return AIAgentIdentityPage{}, err
			}
			diagnostics = append(diagnostics, providers.SourceError{
				Collector: aiAgentIdentityCollectorName,
				SourceID:  fmt.Sprintf("adapter:%d", apiIndex),
				Code:      "ai_agent_identity_adapter_failed",
				Message:   fmt.Sprintf("ai agent identity adapter %d failed: %v", apiIndex, err),
				Retryable: isRetryable(err),
			})
			apiIndex++
			sourceToken = ""
			continue
		}
		page.Diagnostics = append(diagnostics, page.Diagnostics...)
		if strings.TrimSpace(page.NextToken) != "" {
			page.NextToken = formatCompositeAIAgentIdentityToken(apiIndex, page.NextToken)
			return page, nil
		}
		if apiIndex+1 < len(a.apis) {
			page.NextToken = formatCompositeAIAgentIdentityToken(apiIndex+1, "")
		}
		if len(page.Records) > 0 || len(page.Diagnostics) > 0 {
			return page, nil
		}
		apiIndex++
		sourceToken = ""
	}
	return AIAgentIdentityPage{Diagnostics: diagnostics}, nil
}

func parseCompositeAIAgentIdentityToken(token string) (int, string, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return 0, "", nil
	}
	index, sourceToken, ok := strings.Cut(trimmed, ":")
	if !ok {
		return 0, "", fmt.Errorf("invalid ai agent identity pagination token")
	}
	parsed, err := strconv.Atoi(index)
	if err != nil || parsed < 0 {
		return 0, "", fmt.Errorf("invalid ai agent identity pagination token")
	}
	return parsed, sourceToken, nil
}

func formatCompositeAIAgentIdentityToken(apiIndex int, sourceToken string) string {
	return strconv.Itoa(apiIndex) + ":" + strings.TrimSpace(sourceToken)
}
