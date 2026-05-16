package auth

import (
	"errors"
	"strings"

	"github.com/workos/workos-go/v6/pkg/workos_errors"
)

const (
	WorkOSMFAModeEnrollment = "enrollment"
	WorkOSMFAModeChallenge  = "challenge"
)

type WorkOSMFAFactor struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type WorkOSMFARequired struct {
	Mode                       string
	User                       WorkOSProfile
	PendingAuthenticationToken string
	AuthenticationFactors      []WorkOSMFAFactor
}

func (e *WorkOSMFARequired) Error() string {
	mode := strings.TrimSpace(e.Mode)
	if mode == "" {
		mode = "completion"
	}
	return "workos mfa " + mode + " required"
}

type WorkOSMFAEnrollRequest struct {
	UserID     string
	TOTPIssuer string
	TOTPUser   string
}

type WorkOSMFAEnrollResponse struct {
	FactorID    string
	FactorType  string
	ChallengeID string
	ExpiresAt   string
	TOTPQRCode  string
	TOTPSecret  string
	TOTPURI     string
}

type WorkOSMFAChallengeRequest struct {
	FactorID string
}

type WorkOSMFAChallengeResponse struct {
	ChallengeID string
	FactorID    string
	ExpiresAt   string
}

type WorkOSMFAVerifyRequest struct {
	PendingAuthenticationToken string
	AuthenticationChallengeID  string
	Code                       string
	IPAddress                  string
	UserAgent                  string
}

func AsWorkOSMFARequired(err error) (*WorkOSMFARequired, bool) {
	if err == nil {
		return nil, false
	}
	var required *WorkOSMFARequired
	if errors.As(err, &required) && required != nil {
		return required, true
	}
	var enrollmentErr *workos_errors.MFAEnrollmentError
	if errors.As(err, &enrollmentErr) && enrollmentErr != nil {
		return &WorkOSMFARequired{
			Mode:                       WorkOSMFAModeEnrollment,
			User:                       workOSProfileFromUser(enrollmentErr.User, ""),
			PendingAuthenticationToken: enrollmentErr.PendingAuthenticationToken,
		}, true
	}
	var challengeErr *workos_errors.MFAChallengeError
	if errors.As(err, &challengeErr) && challengeErr != nil {
		return &WorkOSMFARequired{
			Mode:                       WorkOSMFAModeChallenge,
			User:                       workOSProfileFromUser(challengeErr.User, ""),
			PendingAuthenticationToken: challengeErr.PendingAuthenticationToken,
			AuthenticationFactors:      workOSMFAFactorsFromWorkOSError(challengeErr.AuthenticationFactors),
		}, true
	}
	var httpErr workos_errors.HTTPError
	if errors.As(err, &httpErr) {
		switch httpErr.ErrorCode {
		case workos_errors.MFAEnrollmentCode:
			required := &WorkOSMFARequired{
				Mode:                       WorkOSMFAModeEnrollment,
				PendingAuthenticationToken: httpErr.PendingAuthenticationToken,
			}
			if httpErr.User != nil {
				required.User = workOSProfileFromUser(*httpErr.User, "")
			}
			return required, true
		case workos_errors.MFAChallengeCode:
			required := &WorkOSMFARequired{
				Mode:                       WorkOSMFAModeChallenge,
				PendingAuthenticationToken: httpErr.PendingAuthenticationToken,
				AuthenticationFactors:      workOSMFAFactorsFromWorkOSError(httpErr.AuthenticationFactors),
			}
			if httpErr.User != nil {
				required.User = workOSProfileFromUser(*httpErr.User, "")
			}
			return required, true
		}
	}
	return nil, false
}

func workOSMFAFactorsFromWorkOSError(factors []workos_errors.AuthenticationFactor) []WorkOSMFAFactor {
	if len(factors) == 0 {
		return nil
	}
	result := make([]WorkOSMFAFactor, 0, len(factors))
	for _, factor := range factors {
		if strings.TrimSpace(factor.ID) == "" {
			continue
		}
		result = append(result, WorkOSMFAFactor{
			ID:   strings.TrimSpace(factor.ID),
			Type: string(factor.Type),
		})
	}
	return result
}
