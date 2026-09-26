package oauth2

import (
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lemmego/api/app"
	"github.com/lemmego/api/session"
	"github.com/lemmego/auth"
)

// ownerKey is where the resolved resource owner is put on the context.
const ownerKey = "oauth:owner"

// requireResourceOwner establishes who is granting consent.
//
// It cannot simply call auth.Protected. That answers 401, which is right for
// an API and wrong for a browser flow — a person who is not signed in should
// be sent to sign in. And the scaffold's default configuration runs auth with
// DisableSession, so the user on the context is a map decoded from a JWT
// rather than a live row; this has to read both shapes.
func (p *Provider) requireResourceOwner(c app.Context) error {
	if p.ResourceOwner != nil {
		if id, ok := p.ResourceOwner(c); ok && id != "" {
			c.Set(ownerKey, id)
			return c.Next()
		}
		return p.redirectToLogin(c)
	}

	// Populates the context when it can; the error is not fatal here because
	// the fallbacks below may still find a user.
	_ = auth.Check(c)

	for _, candidate := range []any{c.Get(auth.UserKey), c.Session(auth.UserKey)} {
		if id, ok := subjectID(candidate); ok {
			c.Set(ownerKey, id)
			return c.Next()
		}
	}
	return p.redirectToLogin(c)
}

func (p *Provider) redirectToLogin(c app.Context) error {
	server := p.Server()
	login := "/login"
	if server != nil {
		login = server.cfg.LoginRoute
	}
	return c.SetStatus(http.StatusFound).
		Redirect(login + "?redirect=" + url.QueryEscape(c.Request().URL.RequestURI()))
}

// subjectID reads a user id out of every shape the framework produces.
//
// With sessions the value is the application's own type, satisfying
// auth.UserProvider. With DisableSession — the scaffold's default — it is a
// map[string]any that auth.jwtUser decoded from the token's user claim, which
// Login produced by JSON-marshalling the user. Supporting both is what lets
// the consent screen work without the application changing its auth setup.
func subjectID(candidate any) (string, bool) {
	switch value := candidate.(type) {
	case nil:
		return "", false
	case auth.UserProvider:
		if id := value.GetID(); id != "" {
			return id, true
		}
	case map[string]any:
		for _, key := range []string{"id", "sub", "user_id", "ID"} {
			if id, ok := scalarString(value[key]); ok {
				// auth.Login writes sub as id|username, so the identifier is
				// the part before the separator.
				if key == "sub" {
					id, _, _ = strings.Cut(id, "|")
				}
				if id != "" {
					return id, true
				}
			}
		}
	case string:
		if value != "" {
			return value, true
		}
	case fmt.Stringer:
		if id := value.String(); id != "" {
			return id, true
		}
	}
	return "", false
}

func scalarString(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, typed != ""
	case float64:
		// Every JSON number decodes to float64, which is how a numeric id
		// arrives from a token claim.
		return strconv.FormatFloat(typed, 'f', -1, 64), true
	case int:
		return strconv.Itoa(typed), true
	case int64:
		return strconv.FormatInt(typed, 10), true
	case uint64:
		return strconv.FormatUint(typed, 10), true
	}
	return "", false
}

// showConsent renders the authorization screen.
func (p *Provider) showConsent(c app.Context) error {
	server := p.Server()
	if server == nil {
		return c.SetStatus(http.StatusInternalServerError).JSON(app.M{"error": ErrCodeServerError})
	}

	request, err := server.ParseAuthorizeRequest(c.RequestContext(), c.Request().URL.Query())
	if err != nil {
		return p.renderAuthorizeError(c, err)
	}

	owner, _ := c.Get(ownerKey).(string)

	// A client the application itself owns has nobody to ask.
	if server.cfg.SkipConsentForFirstParty && request.Client.FirstParty {
		return p.completeAuthorization(c, server, request, owner, request.Scopes)
	}

	pending, err := server.NewPendingConsent(request, sessionID(c))
	if err != nil {
		return p.renderAuthorizeError(c, err)
	}
	encoded, err := pending.Encode()
	if err != nil {
		return p.renderAuthorizeError(c, err)
	}
	c.PutSession(SessionKey, encoded)

	csrfToken, _ := c.Get("_token").(string)
	data := server.ConsentDataFor(request, csrfToken, pending.Nonce)

	view := p.ConsentView
	if view == nil {
		view = renderConsent
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-Control", "no-store")
	c.WriteStatus(http.StatusOK)
	return view(c.ResponseWriter(), data)
}

// decideConsent records the user's answer.
//
// The authorization is rebuilt from the session rather than from the posted
// body. That is what stops parameter substitution: a page that displayed
// "read" cannot post back "read write admin", because the scopes granted are
// the ones that were shown.
func (p *Provider) decideConsent(c app.Context) error {
	server := p.Server()
	if server == nil {
		return c.SetStatus(http.StatusInternalServerError).JSON(app.M{"error": ErrCodeServerError})
	}

	raw := c.PopSession(SessionKey)
	encoded, _ := raw.(string)
	if encoded == "" {
		return p.renderAuthorizeError(c, errorf(ErrCodeInvalidRequest,
			"this authorization has expired; start again from the application"))
	}
	pending, err := DecodePendingConsent(encoded)
	if err != nil {
		return p.renderAuthorizeError(c, errorf(ErrCodeInvalidRequest, "this authorization is no longer valid"))
	}

	// Single use, bound to the session and to the request that was shown.
	if !pending.Matches(c.Request().PostFormValue("_oauth_nonce"), server.now()) {
		return p.renderAuthorizeError(c, errorf(ErrCodeInvalidRequest,
			"this form is no longer valid; start again from the application"))
	}

	client, err := server.store.Client(c.RequestContext(), pending.ClientID)
	if err != nil {
		return p.renderAuthorizeError(c, errorf(ErrCodeInvalidClient, "unknown client"))
	}
	request := pending.Request(client)

	if c.Request().PostFormValue("decision") != "approve" {
		denial := server.DenyAuthorization(request)
		return c.SetStatus(http.StatusFound).Redirect(denial.Location())
	}

	owner, _ := c.Get(ownerKey).(string)
	approved := request.Scopes
	if narrowed := c.Request().PostForm["scope"]; len(narrowed) > 0 {
		approved = ParseScopes(strings.Join(narrowed, " "))
	}
	return p.completeAuthorization(c, server, request, owner, approved)
}

func (p *Provider) completeAuthorization(c app.Context, server *Server, request *AuthorizeRequest, owner string, approved Scopes) error {
	code, err := server.GrantAuthorization(c.RequestContext(), request, owner, approved)
	if err != nil {
		return p.renderAuthorizeError(c, err)
	}
	return c.SetStatus(http.StatusFound).
		Redirect(SuccessRedirect(request.RedirectURI, code, request.State))
}

// renderAuthorizeError sends the user somewhere sensible.
//
// A RedirectError goes back to the client, as RFC 6749 section 4.1.2.1 wants.
// Anything else is rendered here, because it was discovered before the
// redirect target could be trusted — redirecting it would make this endpoint
// an open redirector.
func (p *Provider) renderAuthorizeError(c app.Context, err error) error {
	var redirect *RedirectError
	if errors.As(err, &redirect) {
		return c.SetStatus(http.StatusFound).Redirect(redirect.Location())
	}

	protocolErr := asProtocolError(err)
	if c.WantsJSON() {
		return c.SetStatus(statusFor(protocolErr.Code)).JSON(app.M{
			"error":             protocolErr.Code,
			"error_description": protocolErr.Description,
		})
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.WriteStatus(statusFor(protocolErr.Code))
	_, writeErr := fmt.Fprintf(c.ResponseWriter(),
		"<!doctype html><meta charset=utf-8><title>Authorization failed</title>"+
			"<body style=\"font:16px/1.5 system-ui;margin:3rem auto;max-width:34rem;padding:0 1rem\">"+
			"<h1 style=\"font-size:1.25rem\">This authorization request cannot be completed</h1>"+
			"<p>%s</p><p style=\"color:#666;font-size:.875rem\">You have not been redirected, because the "+
			"request did not identify an application we could safely return you to.</p>",
		template.HTMLEscapeString(protocolErr.Description))
	return writeErr
}

// showDeviceForm asks for a user code, RFC 8628 section 3.3.
func (p *Provider) showDeviceForm(c app.Context) error {
	server := p.Server()
	if server == nil {
		return c.SetStatus(http.StatusInternalServerError).JSON(app.M{"error": ErrCodeServerError})
	}

	userCode := c.Request().URL.Query().Get("user_code")
	if userCode == "" {
		return p.renderDevicePrompt(c, "", "")
	}
	// A code arriving in the URL is the verification_uri_complete form, so
	// the screen can go straight to asking for a decision.
	return p.renderDeviceConfirm(c, server, userCode)
}

// submitDeviceCode handles the typed code and the decision.
func (p *Provider) submitDeviceCode(c app.Context) error {
	server := p.Server()
	if server == nil {
		return c.SetStatus(http.StatusInternalServerError).JSON(app.M{"error": ErrCodeServerError})
	}

	userCode := c.Request().PostFormValue("user_code")
	decision := c.Request().PostFormValue("decision")
	owner, _ := c.Get(ownerKey).(string)

	switch decision {
	case "approve":
		if err := server.ApproveDevice(c.RequestContext(), userCode, owner, nil); err != nil {
			return p.renderDevicePrompt(c, userCode, asProtocolError(err).Description)
		}
		return p.renderDeviceDone(c, "You can go back to your device now.")
	case "deny":
		if err := server.DenyDevice(c.RequestContext(), userCode); err != nil {
			return p.renderDevicePrompt(c, userCode, asProtocolError(err).Description)
		}
		return p.renderDeviceDone(c, "The request was refused.")
	default:
		return p.renderDeviceConfirm(c, server, userCode)
	}
}

func (p *Provider) renderDeviceConfirm(c app.Context, server *Server, userCode string) error {
	device, client, err := server.LookupDeviceAuthorization(c.RequestContext(), userCode, deviceLimitKey(c))
	if err != nil {
		return p.renderDevicePrompt(c, userCode, asProtocolError(err).Description)
	}

	scopes := make([]ConsentScope, 0, len(device.Scopes))
	for _, scope := range device.Scopes {
		scopes = append(scopes, ConsentScope{Name: scope, Description: server.cfg.Scopes[scope]})
	}

	view := p.DeviceView
	if view == nil {
		view = renderDeviceConfirm
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-Control", "no-store")
	c.WriteStatus(http.StatusOK)
	csrfToken, _ := c.Get("_token").(string)
	return view(c.ResponseWriter(), DeviceData{
		UserCode:   FormatUserCode(NormalizeUserCode(userCode)),
		ClientName: client.Name,
		Scopes:     scopes,
		FormAction: server.cfg.RoutePrefix + "/device",
		CSRFToken:  csrfToken,
	})
}

// deviceLimitKey identifies who is guessing, not which code they guessed.
// Keying on the code would let an attacker simply move to the next one.
func deviceLimitKey(c app.Context) string {
	if address := c.Request().Header.Get("X-Forwarded-For"); address != "" {
		host, _, _ := strings.Cut(address, ",")
		return strings.TrimSpace(host)
	}
	host, _, err := net.SplitHostPort(c.Request().RemoteAddr)
	if err != nil {
		return c.Request().RemoteAddr
	}
	return host
}

func sessionID(c app.Context) string {
	if sess, ok := app.Lookup[*session.Session](c.App()); ok && sess != nil {
		return sess.Token(c.RequestContext())
	}
	return ""
}

// renderDevicePrompt asks for a code, optionally with a message explaining
// why the last attempt did not work.
func (p *Provider) renderDevicePrompt(c app.Context, userCode, message string) error {
	server := p.Server()
	action := "/oauth/device"
	if server != nil {
		action = server.cfg.RoutePrefix + "/device"
	}
	csrfToken, _ := c.Get("_token").(string)

	view := p.DeviceView
	if view == nil {
		view = renderDevicePrompt
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-Control", "no-store")
	c.WriteStatus(http.StatusOK)
	return view(c.ResponseWriter(), DeviceData{
		UserCode:   userCode,
		FormAction: action,
		CSRFToken:  csrfToken,
		Error:      message,
	})
}

func (p *Provider) renderDeviceDone(c app.Context, message string) error {
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-Control", "no-store")
	c.WriteStatus(http.StatusOK)
	return renderDeviceDone(c.ResponseWriter(), DeviceData{Message: message})
}
