package oauth2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// userCodeAlphabet is RFC 8628 section 6.1's recommended set: twenty
// characters with no vowels, so no code can spell a word, and none of the
// pairs people confuse when reading a screen aloud — no O against 0, no I or
// L against 1.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// userCodeLength gives 20^8, about 2.6e10, or roughly 34.6 bits.
//
// That is not enough on its own, and is not asked to be: a code lives ten
// minutes, is single use, and the verification endpoint is rate limited. RFC
// 8628 section 5.1 requires the rate limit for exactly this reason.
const userCodeLength = 8

// DeviceAuthorizationResponse is the body of a device authorization request,
// RFC 8628 section 3.2.
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// AuthorizeDevice starts a device authorization.
func (s *Server) AuthorizeDevice(ctx Context, client *Client, params url.Values) (*DeviceAuthorizationResponse, error) {
	if !client.AllowsGrant(GrantDeviceCode) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the device authorization grant")
	}

	scopes, err := s.validateScopes(client, ParseScopes(params.Get("scope")))
	if err != nil {
		return nil, err
	}

	deviceCode, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	family, err := newFamilyID()
	if err != nil {
		return nil, err
	}

	now := s.now()
	// The user code is unique, so a collision must be retried rather than
	// left to overwrite an authorization somebody is already looking at.
	var userCode string
	for attempt := 0; ; attempt++ {
		userCode, err = generateUserCode()
		if err != nil {
			return nil, err
		}
		err = s.store.CreateDeviceCode(ctx, &DeviceCode{
			ID:              hashToken(deviceCode),
			UserCodeHash:    hashToken(NormalizeUserCode(userCode)),
			ClientID:        client.ID,
			Scopes:          scopes,
			FamilyID:        family,
			IntervalSeconds: s.cfg.DeviceInterval,
			ExpiresAt:       now.Add(s.cfg.DeviceCodeTTL),
			CreatedAt:       now,
		})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrDuplicate) {
			return nil, errorf(ErrCodeServerError, "could not record the device authorization").WithCause(err)
		}
		// Three collisions in a 2.6e10 space means something is wrong with
		// the randomness, not that we were unlucky.
		if attempt >= 3 {
			return nil, errorf(ErrCodeServerError, "could not allocate a unique user code")
		}
	}

	verification := s.cfg.URL("/device")
	return &DeviceAuthorizationResponse{
		DeviceCode:      deviceCode,
		UserCode:        FormatUserCode(userCode),
		VerificationURI: verification,
		// RFC 8628 section 3.3.1: the complete form lets a device show a QR
		// code the user can follow without typing anything.
		VerificationURIComplete: verification + "?user_code=" + url.QueryEscape(FormatUserCode(userCode)),
		ExpiresIn:               int64(s.cfg.DeviceCodeTTL / time.Second),
		Interval:                s.cfg.DeviceInterval,
	}, nil
}

func generateUserCode() (string, error) {
	limit := big.NewInt(int64(len(userCodeAlphabet)))
	out := make([]byte, userCodeLength)
	for i := range out {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("oauth2: cannot generate a user code: %w", err)
		}
		out[i] = userCodeAlphabet[n.Int64()]
	}
	return string(out), nil
}

// FormatUserCode renders a code the way it is shown to a person.
func FormatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// NormalizeUserCode reduces what a person typed to the form that was stored.
//
// People retype these from a television screen, so the dash is optional, case
// does not matter, and anything outside the alphabet — a space, a stray
// punctuation mark — is dropped rather than causing a failure they cannot
// see the reason for.
func NormalizeUserCode(input string) string {
	upper := strings.ToUpper(strings.TrimSpace(input))
	out := make([]rune, 0, len(upper))
	for _, r := range upper {
		if strings.ContainsRune(userCodeAlphabet, r) {
			out = append(out, r)
		}
	}
	return string(out)
}

// LookupDeviceAuthorization finds a pending authorization by the code a user
// typed, applying the rate limit RFC 8628 section 5.1 requires.
//
// About 35 bits of entropy is not enough to survive unlimited guessing, so
// the limit is what actually protects it. The key should identify the person
// guessing — their address, their session — not the code, or an attacker
// simply moves to the next code.
func (s *Server) LookupDeviceAuthorization(ctx Context, userCode, limitKey string) (*DeviceCode, *Client, error) {
	if allowed, retryAfter := s.limiter.Allow(ctx, "usercode:"+limitKey, 5, time.Minute); !allowed {
		return nil, nil, &Error{
			Code:        ErrCodeAccessDenied,
			Description: fmt.Sprintf("too many attempts; try again in %d seconds", int(retryAfter.Seconds())+1),
			Status:      429,
		}
	}

	normalised := NormalizeUserCode(userCode)
	if len(normalised) != userCodeLength {
		return nil, nil, errInvalidUserCode
	}

	device, err := s.store.DeviceCodeByUserCode(ctx, hashToken(normalised))
	if errors.Is(err, ErrNotFound) {
		return nil, nil, errInvalidUserCode
	}
	if err != nil {
		return nil, nil, errorf(ErrCodeServerError, "could not read the device authorization").WithCause(err)
	}
	if device.ApprovedAt != nil || device.DeniedAt != nil {
		return nil, nil, errorf(ErrCodeInvalidRequest, "this code has already been used")
	}
	if !device.ExpiresAt.After(s.now()) {
		return nil, nil, errorf(ErrCodeExpiredToken, "this code has expired; start again on your device")
	}

	client, err := s.store.Client(ctx, device.ClientID)
	if err != nil {
		return nil, nil, errorf(ErrCodeServerError, "could not read the client").WithCause(err)
	}
	return device, client, nil
}

// One message for every way a user code can be unusable, so the endpoint
// cannot be used to learn which codes exist.
var errInvalidUserCode = errorf(ErrCodeInvalidGrant, "that code is not valid")

// ApproveDevice records a user's approval, optionally narrowing the scopes.
func (s *Server) ApproveDevice(ctx Context, userCode, userID string, approved Scopes) error {
	normalised := NormalizeUserCode(userCode)
	device, err := s.store.DeviceCodeByUserCode(ctx, hashToken(normalised))
	if err != nil {
		return errInvalidUserCode
	}
	if len(approved) == 0 {
		approved = device.Scopes
	}
	if !approved.Subset(device.Scopes) {
		return errorf(ErrCodeInvalidScope, "the approved scopes exceed what the device requested")
	}

	err = s.store.ApproveDeviceCode(ctx, hashToken(normalised), userID, approved, s.now())
	switch {
	case errors.Is(err, ErrAlreadyDecided):
		return errorf(ErrCodeInvalidRequest, "this code has already been used")
	case errors.Is(err, ErrExpired):
		return errorf(ErrCodeExpiredToken, "this code has expired")
	case errors.Is(err, ErrNotFound):
		return errInvalidUserCode
	case err != nil:
		return errorf(ErrCodeServerError, "could not record the approval").WithCause(err)
	}
	return nil
}

// DenyDevice records a user's refusal.
func (s *Server) DenyDevice(ctx Context, userCode string) error {
	err := s.store.DenyDeviceCode(ctx, hashToken(NormalizeUserCode(userCode)), s.now())
	switch {
	case errors.Is(err, ErrAlreadyDecided):
		return errorf(ErrCodeInvalidRequest, "this code has already been used")
	case errors.Is(err, ErrNotFound):
		return errInvalidUserCode
	case err != nil:
		return errorf(ErrCodeServerError, "could not record the refusal").WithCause(err)
	}
	return nil
}

// ExchangeDeviceCode is the device polling the token endpoint.
func (s *Server) ExchangeDeviceCode(ctx Context, client *Client, params url.Values) (*TokenResponse, error) {
	if !client.AllowsGrant(GrantDeviceCode) {
		return nil, errorf(ErrCodeUnauthorizedClient,
			"this client is not registered for the device authorization grant")
	}

	presented := params.Get("device_code")
	if presented == "" {
		return nil, errorf(ErrCodeInvalidRequest, "device_code is required")
	}
	deviceID := hashToken(presented)

	device, outcome, err := s.store.PollDeviceCode(ctx, deviceID, s.now())
	if errors.Is(err, ErrNotFound) {
		return nil, errorf(ErrCodeInvalidGrant, "the device code is invalid")
	}
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not read the device authorization").WithCause(err)
	}

	// Bound client, before the outcome is acted on: a device code issued to
	// one client must not be redeemable by another.
	if !constantTimeEqual(device.ClientID, client.ID) {
		return nil, errorf(ErrCodeInvalidGrant, "this device code was issued to a different client")
	}

	switch outcome {
	case PollSlowDown:
		return nil, errorf(ErrCodeSlowDown, "polling too frequently; wait for the interval")
	case PollDenied:
		return nil, errorf(ErrCodeAccessDenied, "the request was refused")
	case PollExpired:
		return nil, errorf(ErrCodeExpiredToken, "the device code has expired")
	case PollPending:
		return nil, errorf(ErrCodeAuthorizationPending, "the user has not finished yet")
	}

	issued, response, err := s.issuePair(issueParams{
		UserID:      device.UserID,
		ClientID:    client.ID,
		Scopes:      device.Scopes,
		FamilyID:    device.FamilyID,
		AccessTTL:   s.cfg.AccessTokenTTL,
		RefreshTTL:  s.cfg.RefreshTokenTTL,
		WithRefresh: client.AllowsGrant(GrantRefreshToken),
	})
	if err != nil {
		return nil, errorf(ErrCodeServerError, "could not issue a token").WithCause(err)
	}

	if _, err := s.store.ExchangeDeviceCode(ctx, deviceID, issued, s.now()); err != nil {
		switch {
		case errors.Is(err, ErrCodeReplayed):
			return nil, errorf(ErrCodeInvalidGrant, "this device code has already been used")
		case errors.Is(err, ErrNotApproved):
			return nil, errorf(ErrCodeAuthorizationPending, "the user has not finished yet")
		case errors.Is(err, ErrExpired):
			return nil, errorf(ErrCodeExpiredToken, "the device code has expired")
		}
		return nil, errorf(ErrCodeServerError, "could not complete the authorization").WithCause(err)
	}
	return response, nil
}
