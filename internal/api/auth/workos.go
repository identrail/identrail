package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/workos/workos-go/v6/pkg/mfa"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

const WorkOSProvider = "workos"

var ErrWorkOSUnavailable = errors.New("workos unavailable")

type WorkOSAuthorizationRequest struct {
	RedirectURI    string
	State          string
	ScreenHint     string
	Provider       string
	ProviderScopes []string
}

type WorkOSAuthenticationRequest struct {
	Code      string
	IPAddress string
	UserAgent string
}

type WorkOSProfile struct {
	ID                string          `json:"id"`
	Email             string          `json:"email"`
	OrganizationID    string          `json:"organization_id,omitempty"`
	FirstName         string          `json:"first_name,omitempty"`
	LastName          string          `json:"last_name,omitempty"`
	EmailVerified     bool            `json:"email_verified"`
	ProfilePictureURL string          `json:"profile_picture_url,omitempty"`
	RawClaims         json.RawMessage `json:"raw_claims,omitempty"`
}

type WorkOSAuthentication struct {
	User                 WorkOSProfile
	OrganizationID       string
	AuthenticationMethod string
}

type WorkOSClient interface {
	AuthorizationURL(input WorkOSAuthorizationRequest) (string, error)
	AuthenticateWithCode(ctx context.Context, input WorkOSAuthenticationRequest) (WorkOSAuthentication, error)
	EnrollAuthFactor(ctx context.Context, input WorkOSMFAEnrollRequest) (WorkOSMFAEnrollResponse, error)
	ChallengeAuthFactor(ctx context.Context, input WorkOSMFAChallengeRequest) (WorkOSMFAChallengeResponse, error)
	AuthenticateWithTOTP(ctx context.Context, input WorkOSMFAVerifyRequest) (WorkOSAuthentication, error)
}

type WorkOSSDKClient struct {
	clientID string
	client   *usermanagement.Client
	mfa      *mfa.Client
}

func NewWorkOSSDKClient(apiKey string, clientID string) *WorkOSSDKClient {
	return &WorkOSSDKClient{
		clientID: strings.TrimSpace(clientID),
		client:   usermanagement.NewClient(strings.TrimSpace(apiKey)),
		mfa:      &mfa.Client{APIKey: strings.TrimSpace(apiKey)},
	}
}

func (c *WorkOSSDKClient) AuthorizationURL(input WorkOSAuthorizationRequest) (string, error) {
	if c == nil || c.client == nil || c.clientID == "" {
		return "", ErrWorkOSUnavailable
	}
	opts := usermanagement.GetAuthorizationURLOpts{
		ClientID:       c.clientID,
		RedirectURI:    strings.TrimSpace(input.RedirectURI),
		Provider:       strings.TrimSpace(input.Provider),
		State:          strings.TrimSpace(input.State),
		ProviderScopes: append([]string(nil), input.ProviderScopes...),
	}
	if opts.Provider == "" {
		opts.Provider = "authkit"
	}
	if strings.EqualFold(strings.TrimSpace(input.ScreenHint), "sign-up") {
		opts.ScreenHint = usermanagement.SignUp
	}
	authorizationURL, err := c.client.GetAuthorizationURL(opts)
	if err != nil {
		return "", err
	}
	return authorizationURL.String(), nil
}

func (c *WorkOSSDKClient) AuthenticateWithCode(ctx context.Context, input WorkOSAuthenticationRequest) (WorkOSAuthentication, error) {
	if c == nil || c.client == nil || c.clientID == "" {
		return WorkOSAuthentication{}, ErrWorkOSUnavailable
	}
	response, err := c.client.AuthenticateWithCode(ctx, usermanagement.AuthenticateWithCodeOpts{
		ClientID:  c.clientID,
		Code:      strings.TrimSpace(input.Code),
		IPAddress: strings.TrimSpace(input.IPAddress),
		UserAgent: strings.TrimSpace(input.UserAgent),
	})
	if err != nil {
		return WorkOSAuthentication{}, normalizeWorkOSAuthenticationError(err)
	}
	return workOSAuthenticationFromResponse(response), nil
}

func (c *WorkOSSDKClient) EnrollAuthFactor(ctx context.Context, input WorkOSMFAEnrollRequest) (WorkOSMFAEnrollResponse, error) {
	if c == nil || c.client == nil || c.clientID == "" {
		return WorkOSMFAEnrollResponse{}, ErrWorkOSUnavailable
	}
	response, err := c.client.EnrollAuthFactor(ctx, usermanagement.EnrollAuthFactorOpts{
		User:       strings.TrimSpace(input.UserID),
		Type:       mfa.TOTP,
		TOTPIssuer: strings.TrimSpace(input.TOTPIssuer),
		TOTPUser:   strings.TrimSpace(input.TOTPUser),
	})
	if err != nil {
		return WorkOSMFAEnrollResponse{}, normalizeWorkOSAuthenticationError(err)
	}
	return WorkOSMFAEnrollResponse{
		FactorID:    response.Factor.ID,
		FactorType:  string(response.Factor.Type),
		ChallengeID: response.Challenge.ID,
		ExpiresAt:   response.Challenge.ExpiresAt,
		TOTPQRCode:  response.Factor.TOTP.QRCode,
		TOTPSecret:  response.Factor.TOTP.Secret,
		TOTPURI:     response.Factor.TOTP.URI,
	}, nil
}

func (c *WorkOSSDKClient) ChallengeAuthFactor(ctx context.Context, input WorkOSMFAChallengeRequest) (WorkOSMFAChallengeResponse, error) {
	if c == nil || c.mfa == nil || c.clientID == "" {
		return WorkOSMFAChallengeResponse{}, ErrWorkOSUnavailable
	}
	response, err := c.mfa.ChallengeFactor(ctx, mfa.ChallengeFactorOpts{
		FactorID: strings.TrimSpace(input.FactorID),
	})
	if err != nil {
		return WorkOSMFAChallengeResponse{}, normalizeWorkOSAuthenticationError(err)
	}
	return WorkOSMFAChallengeResponse{
		ChallengeID: response.ID,
		FactorID:    response.FactorID,
		ExpiresAt:   response.ExpiresAt,
	}, nil
}

func (c *WorkOSSDKClient) AuthenticateWithTOTP(ctx context.Context, input WorkOSMFAVerifyRequest) (WorkOSAuthentication, error) {
	if c == nil || c.client == nil || c.clientID == "" {
		return WorkOSAuthentication{}, ErrWorkOSUnavailable
	}
	response, err := c.client.AuthenticateWithTOTP(ctx, usermanagement.AuthenticateWithTOTPOpts{
		ClientID:                   c.clientID,
		Code:                       strings.TrimSpace(input.Code),
		IPAddress:                  strings.TrimSpace(input.IPAddress),
		UserAgent:                  strings.TrimSpace(input.UserAgent),
		PendingAuthenticationToken: strings.TrimSpace(input.PendingAuthenticationToken),
		AuthenticationChallengeID:  strings.TrimSpace(input.AuthenticationChallengeID),
	})
	if err != nil {
		return WorkOSAuthentication{}, normalizeWorkOSAuthenticationError(err)
	}
	return workOSAuthenticationFromResponse(response), nil
}

func normalizeWorkOSAuthenticationError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrWorkOSUnavailable
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return ErrWorkOSUnavailable
	}
	if required, ok := AsWorkOSMFARequired(err); ok {
		return required
	}
	return err
}

func workOSAuthenticationFromResponse(response usermanagement.AuthenticateResponse) WorkOSAuthentication {
	profile := workOSProfileFromUser(response.User, response.OrganizationID)
	return WorkOSAuthentication{
		User:                 profile,
		OrganizationID:       response.OrganizationID,
		AuthenticationMethod: string(response.AuthenticationMethod),
	}
}

func workOSProfileFromUser(user usermanagement.User, organizationID string) WorkOSProfile {
	rawClaims, _ := json.Marshal(user)
	return WorkOSProfile{
		ID:                user.ID,
		Email:             user.Email,
		OrganizationID:    organizationID,
		FirstName:         user.FirstName,
		LastName:          user.LastName,
		EmailVerified:     user.EmailVerified,
		ProfilePictureURL: user.ProfilePictureURL,
		RawClaims:         rawClaims,
	}
}
