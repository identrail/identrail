package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

const WorkOSProvider = "workos"

var ErrWorkOSUnavailable = errors.New("workos unavailable")

type WorkOSAuthorizationRequest struct {
	RedirectURI string
	State       string
	ScreenHint  string
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
}

type WorkOSSDKClient struct {
	clientID string
	client   *usermanagement.Client
}

func NewWorkOSSDKClient(apiKey string, clientID string) *WorkOSSDKClient {
	return &WorkOSSDKClient{
		clientID: strings.TrimSpace(clientID),
		client:   usermanagement.NewClient(strings.TrimSpace(apiKey)),
	}
}

func (c *WorkOSSDKClient) AuthorizationURL(input WorkOSAuthorizationRequest) (string, error) {
	if c == nil || c.client == nil || c.clientID == "" {
		return "", ErrWorkOSUnavailable
	}
	opts := usermanagement.GetAuthorizationURLOpts{
		ClientID:    c.clientID,
		RedirectURI: strings.TrimSpace(input.RedirectURI),
		Provider:    "authkit",
		State:       strings.TrimSpace(input.State),
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
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return WorkOSAuthentication{}, ErrWorkOSUnavailable
		}
		var netErr net.Error
		if errors.As(err, &netErr) {
			return WorkOSAuthentication{}, ErrWorkOSUnavailable
		}
		return WorkOSAuthentication{}, err
	}
	rawClaims, _ := json.Marshal(response.User)
	return WorkOSAuthentication{
		User: WorkOSProfile{
			ID:                response.User.ID,
			Email:             response.User.Email,
			OrganizationID:    response.OrganizationID,
			FirstName:         response.User.FirstName,
			LastName:          response.User.LastName,
			EmailVerified:     response.User.EmailVerified,
			ProfilePictureURL: response.User.ProfilePictureURL,
			RawClaims:         rawClaims,
		},
		OrganizationID:       response.OrganizationID,
		AuthenticationMethod: string(response.AuthenticationMethod),
	}, nil
}
