package oauth2

import (
	"crypto/hmac"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/lemmego/api/app"
)

// ClientRow is one client as the management page shows it.
type ClientRow struct {
	ID           string
	Name         string
	RedirectURIs []string
	GrantTypes   []string
	Public       bool
	Revoked      bool
}

// ClientsData is what the client management page renders.
type ClientsData struct {
	Clients      []ClientRow
	CreateAction string
	RevokeAction string
	CSRFToken    string

	// FormToken is this package's own anti-forgery token, checked
	// independently of the framework's. It is not optional: the REST preset
	// installs no CSRF middleware at all, and a page that can register an
	// OAuth client is not one to leave unprotected.
	FormToken string

	// NewClientID and NewSecret are set once, immediately after a
	// registration, and never again — the secret is stored hashed, so this
	// is genuinely the only time it can be shown.
	NewClientID string
	NewSecret   string

	Error string
}

// ClientsView renders the client management page.
type ClientsView func(w io.Writer, data ClientsData) error

func renderClients(w io.Writer, data ClientsData) error {
	return consentTemplate.ExecuteTemplate(w, "clients", data)
}

// Session keys for the one-time values a redirect carries across.
const (
	sessionNewClientID = "oauth:new_client_id"
	sessionNewSecret   = "oauth:new_secret"
	sessionClientError = "oauth:client_error"
)

// sessionFormToken is where the management page keeps its anti-forgery token.
const sessionFormToken = "oauth:form_token"

// issueFormToken mints a token for the management forms and stores it in the
// session.
//
// Stored rather than derived from the session id, which is what an earlier
// version did and got wrong: scs assigns a session token when the session is
// first written, so on the GET that creates a session there is no id yet to
// derive from, and by the POST there is — the two never matched and every
// registration was rejected as a stale form. Writing it also forces the
// session to exist, which is what makes it stable from then on.
//
// It is per session rather than per form, so several open tabs keep working.
func issueFormToken(c app.Context) (string, error) {
	if existing, ok := c.Session(sessionFormToken).(string); ok && existing != "" {
		return existing, nil
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	c.PutSession(sessionFormToken, token)
	return token, nil
}

// checkFormToken compares a submitted token against the session's, in
// constant time.
func checkFormToken(c app.Context, presented string) bool {
	expected, ok := c.Session(sessionFormToken).(string)
	if !ok || expected == "" || presented == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(presented))
}

// showClients lists the signed-in user's own clients.
//
// Their own, deliberately: a page listing every client in the system would
// need an administrator role to be safe, and would leak the existence of
// every integration to anyone who reached it. Scoping to the owner makes it
// safe by construction, which is also the model Passport uses.
func (p *Provider) showClients(c app.Context) error {
	server, owner, err := p.managementContext(c)
	if err != nil {
		return err
	}

	clients, listErr := server.store.ClientsForUser(c.RequestContext(), owner)
	if listErr != nil {
		return p.renderClientsPage(c, server, owner, nil, "Your clients could not be loaded.")
	}
	return p.renderClientsPage(c, server, owner, clients, "")
}

func (p *Provider) renderClientsPage(c app.Context, server *Server, owner string, clients []*Client, message string) error {
	rows := make([]ClientRow, 0, len(clients))
	for _, client := range clients {
		rows = append(rows, ClientRow{
			ID:           client.ID,
			Name:         client.Name,
			RedirectURIs: client.RedirectURIs,
			GrantTypes:   client.GrantTypes,
			Public:       client.IsPublic(),
			Revoked:      client.Revoked,
		})
	}

	token, err := issueFormToken(c)
	if err != nil {
		return c.SetStatus(http.StatusInternalServerError).JSON(app.M{"error": ErrCodeServerError})
	}

	if message == "" {
		message, _ = c.PopSession(sessionClientError).(string)
	}
	csrfToken, _ := c.Get("_token").(string)

	data := ClientsData{
		Clients:      rows,
		CreateAction: server.cfg.RoutePrefix + "/clients",
		RevokeAction: server.cfg.RoutePrefix + "/clients/revoke",
		CSRFToken:    csrfToken,
		FormToken:    token,
		Error:        message,
	}
	// Shown once, then gone: the secret is stored hashed and cannot be
	// recovered, so a refresh must not redisplay it as though it could.
	data.NewClientID, _ = c.PopSession(sessionNewClientID).(string)
	data.NewSecret, _ = c.PopSession(sessionNewSecret).(string)

	view := p.ClientsView
	if view == nil {
		view = renderClients
	}
	c.SetHeader("Content-Type", "text/html; charset=utf-8")
	c.SetHeader("Cache-Control", "no-store")
	c.WriteStatus(http.StatusOK)
	return view(c.ResponseWriter(), data)
}

// createClient registers a client owned by the signed-in user.
func (p *Provider) createClient(c app.Context) error {
	server, owner, err := p.managementContext(c)
	if err != nil {
		return err
	}
	if !checkFormToken(c, c.Request().PostFormValue("_oauth_form")) {
		return p.clientError(c, server, "That form is no longer valid. Please try again.")
	}

	name := strings.TrimSpace(c.Request().PostFormValue("name"))
	if name == "" {
		return p.clientError(c, server, "A name is required.")
	}
	if len(name) > 255 {
		return p.clientError(c, server, "That name is too long.")
	}

	redirect := strings.TrimSpace(c.Request().PostFormValue("redirect_uri"))
	kind := c.Request().PostFormValue("kind")

	var grants []string
	switch kind {
	case "machine":
		grants = []string{GrantClientCredentials}
	case "device":
		grants = []string{GrantDeviceCode, GrantRefreshToken}
	default:
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
		if redirect == "" {
			return p.clientError(c, server, "A redirect URI is required for this type of client.")
		}
	}

	var redirects []string
	if redirect != "" {
		if err := ValidateRedirectURI(redirect); err != nil {
			return p.clientError(c, server, asProtocolError(err).Description)
		}
		redirects = []string{redirect}
	}

	id, err := randomToken(16)
	if err != nil {
		return p.clientError(c, server, "The client could not be created.")
	}

	client := &Client{
		ID:           id,
		UserID:       owner,
		Name:         name,
		RedirectURIs: redirects,
		GrantTypes:   grants,
		Confidential: kind != "public",
		CreatedAt:    server.now(),
		UpdatedAt:    server.now(),
	}

	var secret string
	if client.Confidential {
		secret, err = randomToken(32)
		if err != nil {
			return p.clientError(c, server, "The client could not be created.")
		}
		client.SecretHash = HashSecret(secret)
	}

	if err := server.store.CreateClient(c.RequestContext(), client); err != nil {
		return p.clientError(c, server, "The client could not be created.")
	}

	c.PutSession(sessionNewClientID, client.ID)
	if secret != "" {
		c.PutSession(sessionNewSecret, secret)
	}
	// Redirect after post, so a refresh does not re-register a client.
	return c.SetStatus(http.StatusFound).Redirect(server.cfg.RoutePrefix + "/clients")
}

// revokeClient revokes a client the signed-in user owns, and every token
// issued to it.
func (p *Provider) revokeClient(c app.Context) error {
	server, owner, err := p.managementContext(c)
	if err != nil {
		return err
	}
	if !checkFormToken(c, c.Request().PostFormValue("_oauth_form")) {
		return p.clientError(c, server, "That form is no longer valid. Please try again.")
	}

	clientID := c.Request().PostFormValue("client_id")
	client, err := server.store.Client(c.RequestContext(), clientID)
	if err != nil {
		// Ownership is checked before anything is said about the client, so
		// this page cannot be used to find out which client ids exist.
		return p.clientError(c, server, "No such client.")
	}
	if !constantTimeEqual(client.UserID, owner) || owner == "" {
		return p.clientError(c, server, "No such client.")
	}

	if err := server.store.RevokeClient(c.RequestContext(), clientID, server.now()); err != nil {
		return p.clientError(c, server, "The client could not be revoked.")
	}
	return c.SetStatus(http.StatusFound).Redirect(server.cfg.RoutePrefix + "/clients")
}

// managementContext resolves the server and the signed-in owner.
func (p *Provider) managementContext(c app.Context) (*Server, string, error) {
	server := p.Server()
	if server == nil {
		return nil, "", c.SetStatus(http.StatusInternalServerError).
			JSON(app.M{"error": ErrCodeServerError, "error_description": "the oauth2 server is not configured"})
	}
	owner, _ := c.Get(ownerKey).(string)
	if owner == "" {
		// requireResourceOwner runs before this and redirects anonymous
		// visitors, so reaching here means it was bypassed.
		return nil, "", errors.New("oauth2: no resource owner on a management route")
	}
	return server, owner, nil
}

// clientError re-renders the page with a message rather than redirecting, so
// what the user typed is not lost to a redirect they did not ask for.
func (p *Provider) clientError(c app.Context, server *Server, message string) error {
	owner, _ := c.Get(ownerKey).(string)
	clients, _ := server.store.ClientsForUser(c.RequestContext(), owner)
	return p.renderClientsPage(c, server, owner, clients, message)
}
