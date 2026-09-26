package oauth2

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/lemmego/api/app"
	"github.com/lemmego/api/config"
	"github.com/lemmego/api/db"
)

// Provider wires the OAuth2 authorization server into the application
// lifecycle.
type Provider struct {
	// Config overrides what is read from the oauth configuration section.
	Config *Config

	// Store overrides where protocol state is kept. Left nil, the provider
	// builds a SQL store over the application's database connection.
	Store Store

	// ConsentView replaces the built-in consent screen. The default is one
	// self-contained HTML document with no external assets, which is what
	// lets it work whether the project renders with Go templates, Templ or
	// Inertia. Replace it to match the application's own design — an Inertia
	// project must, since its pages are components in a JavaScript bundle
	// this package knows nothing about.
	ConsentView ConsentView

	// DeviceView replaces the device verification screens.
	DeviceView DeviceView

	// ClientsView replaces the client management page.
	ClientsView ClientsView

	// ResourceOwner identifies who is granting consent, overriding the
	// default that reads the auth package's user. Return false to send the
	// visitor to the login route.
	ResourceOwner func(c app.Context) (string, bool)

	// UserResolver loads the application's user for a token subject, so a
	// handler written against auth.AuthUser receives a real user rather than
	// the token's principal. Optional.
	UserResolver UserResolver

	mu       sync.RWMutex
	resolved *Config
	store    Store
	server   *Server
}

var (
	_ app.Provider            = (*Provider)(nil)
	_ app.PublishableProvider = (*Provider)(nil)
)

// Provide resolves configuration, opens the store and builds the server.
func (p *Provider) Provide(a app.App) error {
	section, _ := a.Config().Get("oauth").(config.M)

	cfg, err := resolveConfig(p.Config, section)
	if err != nil {
		return err
	}

	// A wrong issuer breaks every consumer of a token and is invisible until
	// somebody integrates against it, so say so at boot rather than leaving
	// it to be discovered later.
	if a.InProduction() {
		if cfg.Issuer == "" {
			slog.Error("oauth: no issuer is configured; every token will carry an empty iss claim. " +
				"Set OAUTH_ISSUER or APP_URL to this application's public URL")
		} else if isLocalIssuer(cfg.Issuer) {
			slog.Error("oauth: the issuer points at localhost in production, so tokens will not "+
				"validate anywhere else", "issuer", cfg.Issuer)
		}
	}

	store, err := p.resolveStore(a, cfg)
	if err != nil {
		return err
	}

	server, err := NewServer(cfg, store, a)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.resolved, p.store, p.server = cfg, store, server
	p.mu.Unlock()

	a.AddService(cfg)
	a.AddService(store)
	a.AddService(server)
	return nil
}

func (p *Provider) resolveStore(a app.App, cfg *Config) (Store, error) {
	if p.Store != nil {
		return p.Store, nil
	}
	if store, ok := app.Lookup[Store](a); ok && store != nil {
		return store, nil
	}

	conn, ok := db.Resolve(a)
	if !ok {
		return nil, errNoDatabase
	}
	return NewSQLStore(conn, WithTablePrefix(cfg.TablePrefix))
}

// errNoDatabase has to be self-sufficient: registerProviders turns a Provide
// error into a panic, which prints a goroutine dump, so the actionable part
// goes first and the reader should not need to look anything up.
var errNoDatabase = fmt.Errorf(`oauth2: this application has no database, and an OAuth2 server cannot run without one.

Clients, authorization codes, refresh tokens and the revocation list are all
persisted, so there is nothing sensible to fall back to.

To use OAuth2:
  1. configure a connection in internal/configs/database.go and set DB_CONNECTION
  2. add a connector to bootstrap/providers.go, above &oauth2.Provider{}:
     &ormconnector.Provider{} | &gormconnector.Provider{} | &bunconnector.Provider{}
  3. lemmego publish --tags=migrations && go build ./... && lemmego run migrate up

Or supply storage yourself: &oauth2.Provider{Store: myStore}`)

func isLocalIssuer(issuer string) bool {
	lowered := strings.ToLower(issuer)
	for _, marker := range []string{"localhost", "127.0.0.1", "[::1]", "0.0.0.0"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

// Server returns the built server, once Provide has run.
func (p *Provider) Server() *Server {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.server
}
