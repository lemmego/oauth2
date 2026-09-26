package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"
)

//go:embed views/*.html
var viewFS embed.FS

// ConsentScope is one permission as it is shown to a person.
type ConsentScope struct {
	Name        string
	Description string
}

// ConsentData is what a consent screen renders.
//
// It carries everything a custom screen needs, so an application overriding
// the view never has to reach back into the server for context.
type ConsentData struct {
	ClientID     string
	ClientName   string
	Scopes       []ConsentScope
	RedirectURI  string
	RedirectHost string
	State        string

	// FormAction is where the decision is posted. It carries the
	// authorization parameters, so a screen rendered by a different
	// framework does not have to reconstruct them.
	FormAction string

	// CSRFToken is the framework's token when one is present. It may be
	// empty: the REST preset installs no CSRF middleware at all, which is
	// why Nonce exists and is not optional.
	CSRFToken string

	// Nonce is this package's own single-use token, checked independently of
	// the framework's CSRF.
	Nonce string

	// Untrusted marks a client the application does not own, so a screen can
	// say so.
	Untrusted bool
}

// ConsentView renders the consent screen. Returning an error from one is
// reported as a server error.
type ConsentView func(w io.Writer, data ConsentData) error

// dict lets the shared head partial take a title without every caller's data
// type growing a field only the head uses.
var viewFuncs = template.FuncMap{
	"dict": func(values ...any) map[string]any {
		out := map[string]any{}
		for i := 0; i+1 < len(values); i += 2 {
			key, _ := values[i].(string)
			out[key] = values[i+1]
		}
		return out
	},
}

var consentTemplate = template.Must(
	template.New("oauth2").Funcs(viewFuncs).ParseFS(viewFS, "views/*.html"))

// renderConsent is the default screen: one self-contained HTML document with
// inline styles, no JavaScript and no external assets.
//
// Self-contained is what makes it work regardless of the application's
// frontend. A project using Templ or Inertia has no Go template cache to
// render through and no page component for this route, so anything that
// depended on either would work for one project and fail for the next.
func renderConsent(w io.Writer, data ConsentData) error {
	return consentTemplate.ExecuteTemplate(w, "consent", data)
}

// ConsentDataFor builds what a consent screen shows.
func (s *Server) ConsentDataFor(request *AuthorizeRequest, csrfToken, nonce string) ConsentData {
	scopes := make([]ConsentScope, 0, len(request.Scopes))
	for _, scope := range request.Scopes {
		description, known := s.cfg.Scopes[scope]
		if !known && scope == Wildcard {
			description = "Full access to everything in your account"
		}
		scopes = append(scopes, ConsentScope{Name: scope, Description: description})
	}

	host := request.RedirectURI
	if parsed, err := url.Parse(request.RedirectURI); err == nil && parsed.Host != "" {
		host = parsed.Host
	}

	return ConsentData{
		ClientID:     request.Client.ID,
		ClientName:   request.Client.Name,
		Scopes:       scopes,
		RedirectURI:  request.RedirectURI,
		RedirectHost: host,
		State:        request.State,
		FormAction:   s.cfg.RoutePrefix + "/authorize?" + consentQuery(request).Encode(),
		CSRFToken:    csrfToken,
		Nonce:        nonce,
		Untrusted:    !request.Client.FirstParty,
	}
}

func consentQuery(request *AuthorizeRequest) url.Values {
	values := url.Values{
		"client_id":     {request.Client.ID},
		"response_type": {"code"},
		"redirect_uri":  {request.RedirectURI},
		"scope":         {request.Scopes.String()},
	}
	if request.State != "" {
		values.Set("state", request.State)
	}
	if request.CodeChallenge != "" {
		values.Set("code_challenge", request.CodeChallenge)
		values.Set("code_challenge_method", request.CodeChallengeMethod)
	}
	return values
}

// PendingConsent is the authorization a user was actually shown.
//
// It is kept in the session and re-read when the decision arrives, so the
// grant is built from what was displayed rather than from the POST body. That
// is what stops parameter substitution: without it, a page showing "read"
// could post back "read write admin" and the server would have no way to know
// the user never saw it.
type PendingConsent struct {
	Nonce               string    `json:"nonce"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	State               string    `json:"state"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
}

// SessionKey is where the pending authorization is stored.
const SessionKey = "oauth:consent"

// NewPendingConsent records what the user is about to be shown.
func (s *Server) NewPendingConsent(request *AuthorizeRequest, sessionID string) (*PendingConsent, error) {
	nonce, err := s.consentNonce(request, sessionID)
	if err != nil {
		return nil, err
	}
	return &PendingConsent{
		Nonce:               nonce,
		ClientID:            request.Client.ID,
		RedirectURI:         request.RedirectURI,
		Scopes:              request.Scopes,
		State:               request.State,
		CodeChallenge:       request.CodeChallenge,
		CodeChallengeMethod: request.CodeChallengeMethod,
		ExpiresAt:           s.now().Add(15 * time.Minute),
	}, nil
}

// consentNonce derives a token bound to the session and the request.
//
// It is derived rather than random so that a stateless deployment can verify
// it without storing anything, and it is bound to the session so a nonce
// lifted from one user's page is useless on another's.
func (s *Server) consentNonce(request *AuthorizeRequest, sessionID string) (string, error) {
	ring := s.keys.Load()
	if ring == nil {
		return "", fmt.Errorf("oauth2: no key is available to bind the consent form")
	}
	key, kid := ring.Sign()
	// The signing key's modulus is secret and stable, which is what a MAC
	// key needs; the kid keeps the derivation tied to the active key so a
	// rotation invalidates outstanding forms.
	mac := hmac.New(sha256.New, append([]byte(kid), key.N.Bytes()...))
	fmt.Fprintf(mac, "%s|%s|%s|%s", sessionID, request.Client.ID, request.RedirectURI, request.Scopes.String())
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Matches reports whether a decision belongs to this pending authorization.
func (p *PendingConsent) Matches(nonce string, now time.Time) bool {
	if p == nil || p.Nonce == "" {
		return false
	}
	if now.After(p.ExpiresAt) {
		return false
	}
	return hmac.Equal([]byte(p.Nonce), []byte(nonce))
}

// Request rebuilds the authorization from what the user was shown.
func (p *PendingConsent) Request(client *Client) *AuthorizeRequest {
	return &AuthorizeRequest{
		Client:              client,
		RedirectURI:         p.RedirectURI,
		State:               p.State,
		Scopes:              newScopes(p.Scopes),
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
	}
}

// Encode renders the pending authorization for session storage. Sessions are
// often backed by a store that only takes strings, so JSON rather than gob
// keeps the value portable.
func (p *PendingConsent) Encode() (string, error) {
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

// DecodePendingConsent reverses Encode.
func DecodePendingConsent(raw string) (*PendingConsent, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	var pending PendingConsent
	if err := json.Unmarshal(decoded, &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

// DeviceData is what the device verification screen renders.
type DeviceData struct {
	UserCode   string
	ClientName string
	Scopes     []ConsentScope
	FormAction string
	CSRFToken  string

	// Error is a message to show above the form, such as an unrecognised
	// code, rather than a reason to render a different page.
	Error string

	// Message is shown on the final page once a decision has been recorded.
	Message string
}

// DeviceView renders a device verification screen.
type DeviceView func(w io.Writer, data DeviceData) error

func renderDevicePrompt(w io.Writer, data DeviceData) error {
	return consentTemplate.ExecuteTemplate(w, "device_prompt", data)
}

func renderDeviceConfirm(w io.Writer, data DeviceData) error {
	return consentTemplate.ExecuteTemplate(w, "device_confirm", data)
}

func renderDeviceDone(w io.Writer, data DeviceData) error {
	return consentTemplate.ExecuteTemplate(w, "device_done", data)
}
