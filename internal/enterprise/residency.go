package enterprise

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// ResidencyMode controls how strictly the policy is enforced.
type ResidencyMode string

const (
	// ResidencyModeAdvisory records violations but does not block writes; useful
	// during initial rollout.
	ResidencyModeAdvisory ResidencyMode = "advisory"
	// ResidencyModeStrict refuses writes whose target region is not in the
	// allowlist.
	ResidencyModeStrict ResidencyMode = "strict"
)

// recognizedResidencyRegions enumerates the regions Identrail supports for
// data-residency declarations. Keeping this central avoids accepting typos
// like "us-east1" or "EU-WEST-1" that would silently fail closed at the
// storage layer.
var recognizedResidencyRegions = map[string]struct{}{
	"us-east-1":      {},
	"us-east-2":      {},
	"us-west-2":      {},
	"eu-west-1":      {},
	"eu-central-1":   {},
	"ap-southeast-1": {},
	"ap-southeast-2": {},
	"ap-northeast-1": {},
}

// IsRecognizedResidencyRegion reports whether region is a known data-residency
// region. Comparison is case-insensitive.
func IsRecognizedResidencyRegion(region string) bool {
	_, ok := recognizedResidencyRegions[strings.ToLower(strings.TrimSpace(region))]
	return ok
}

// ResidencyPolicy is the per-organization data-residency contract. A workspace
// or scan whose target region is not in AllowedRegions must be rejected under
// strict mode and recorded as a violation under advisory mode.
type ResidencyPolicy struct {
	OrganizationID string        `json:"organization_id"`
	AllowedRegions []string      `json:"allowed_regions"`
	Mode           ResidencyMode `json:"mode"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// Validate enforces ResidencyPolicy invariants.
func (p ResidencyPolicy) Validate() error {
	if strings.TrimSpace(p.OrganizationID) == "" {
		return fmt.Errorf("residency policy organization_id is required")
	}
	if !validResidencyMode(p.Mode) {
		return fmt.Errorf("residency policy mode %q is not recognized", p.Mode)
	}
	if len(p.AllowedRegions) == 0 {
		return fmt.Errorf("residency policy must declare at least one allowed_region")
	}
	for _, region := range p.AllowedRegions {
		if !IsRecognizedResidencyRegion(region) {
			return fmt.Errorf("residency policy allowed_region %q is not recognized", region)
		}
	}
	return nil
}

// ResidencyDecision is the outcome of evaluating one write against a policy.
type ResidencyDecision struct {
	Allowed bool
	Reason  string
}

// Evaluate decides whether a write targeted at the given region is permitted.
// Under advisory mode the decision always allows the write, but Reason carries
// any violation so the caller can record it for governance.
func (p ResidencyPolicy) Evaluate(region string) ResidencyDecision {
	normalized := strings.ToLower(strings.TrimSpace(region))
	for _, allowed := range p.AllowedRegions {
		if strings.ToLower(strings.TrimSpace(allowed)) == normalized {
			return ResidencyDecision{Allowed: true}
		}
	}
	reason := fmt.Sprintf("region %q is not in the organization's allowed residency set", region)
	if p.Mode == ResidencyModeAdvisory {
		return ResidencyDecision{Allowed: true, Reason: reason}
	}
	return ResidencyDecision{Allowed: false, Reason: reason}
}

// SortedAllowedRegions returns a copy of the allowlist with deterministic
// ordering, convenient for hashing/comparison and stable rendering.
func (p ResidencyPolicy) SortedAllowedRegions() []string {
	out := make([]string, len(p.AllowedRegions))
	for i, r := range p.AllowedRegions {
		out[i] = strings.ToLower(strings.TrimSpace(r))
	}
	sort.Strings(out)
	return out
}

func validResidencyMode(m ResidencyMode) bool {
	switch m {
	case ResidencyModeAdvisory, ResidencyModeStrict:
		return true
	}
	return false
}
