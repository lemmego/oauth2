package oauth2

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/lemmego/api/app"
)

// Context is the context protocol operations take. It is an alias so callers
// are not forced to import context alongside this package for every call.
type Context = context.Context

// Server is the authorization server.
//
// It is concrete rather than an interface: every dependency it has is already
// pluggable through Config, Store, KeySource and Limiter, so an interface
// over the whole thing would only duplicate that surface.
type Server struct {
	cfg   *Config
	store Store
	keys  *keyringHolder

	// clock is injected so expiry can be tested by advancing a variable
	// rather than by sleeping. Every timestamp this package writes and every
	// comparison it makes goes through it.
	clock func() time.Time

	limiter Limiter
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithClock replaces the source of time. Tests use it; nothing else should.
func WithClock(clock func() time.Time) ServerOption {
	return func(s *Server) { s.clock = clock }
}

// WithKeys supplies the signing keys directly, rather than reading them from
// the configured directory.
func WithKeys(source KeySource) ServerOption {
	return func(s *Server) {
		if ring, err := NewKeyring(source); err == nil {
			s.keys.Store(ring)
		}
	}
}

// WithLimiter replaces the rate limiter. The default is per-process, which is
// not enough for a deployment running several; a limiter backed by a shared
// cache is.
func WithLimiter(limiter Limiter) ServerOption {
	return func(s *Server) { s.limiter = limiter }
}

// NewServer builds a server.
//
// Missing signing keys are fatal when the application is serving and a
// warning when it is running a command. That asymmetry is load-bearing:
// providers run before commands, so a server that refused to build without
// keys would make oauth:keys — the command that creates them — permanently
// unreachable.
func NewServer(cfg *Config, store Store, a app.App, opts ...ServerOption) (*Server, error) {
	s := &Server{
		cfg:     cfg,
		store:   store,
		keys:    &keyringHolder{},
		clock:   time.Now,
		limiter: NewMemoryLimiter(),
	}
	for _, opt := range opts {
		opt(s)
	}

	if s.keys.Load() == nil {
		ring, err := NewKeyring(FileKeySource{Dir: cfg.KeysPath})
		switch {
		case err == nil:
			s.keys.Store(ring)
			logKeyring(ring)
		case a != nil && a.RunningInConsole():
			// The command that generates the keys has to be able to run.
			slog.Warn("oauth2: signing keys are not available yet", "error", err)
		default:
			return nil, err
		}
	}
	return s, nil
}

// NewServerWithKeys builds a server from an explicit key source, for tests
// and for a deployment that holds its keys somewhere other than a directory.
func NewServerWithKeys(cfg *Config, store Store, source KeySource, opts ...ServerOption) (*Server, error) {
	ring, err := NewKeyring(source)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		store:   store,
		keys:    &keyringHolder{},
		clock:   time.Now,
		limiter: NewMemoryLimiter(),
	}
	s.keys.Store(ring)
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

func (s *Server) now() time.Time { return s.clock().UTC() }

// Config returns the resolved configuration.
func (s *Server) Config() *Config { return s.cfg }

// Store returns the backing store.
func (s *Server) Store() Store { return s.store }

// Keyring returns the keys currently loaded.
func (s *Server) Keyring() *Keyring { return s.keys.Load() }

// ReloadKeys re-reads the signing keys, so rotation takes effect without a
// restart. The swap is atomic, so a request in flight sees one ring or the
// other and never a half-built one.
func (s *Server) ReloadKeys() error {
	ring, err := NewKeyring(FileKeySource{Dir: s.cfg.KeysPath})
	if err != nil {
		return err
	}
	s.keys.Store(ring)
	logKeyring(ring)
	return nil
}

// TokensCan registers scopes the server will issue, alongside whatever the
// configuration declared.
//
// Registration is an allowlist: a scope that is not registered is rejected
// with invalid_scope rather than quietly dropped, because silently dropping
// one leaves a client believing it has access it was never granted.
func (s *Server) TokensCan(scopes map[string]string) {
	if s.cfg.Scopes == nil {
		s.cfg.Scopes = map[string]string{}
	}
	for scope, description := range scopes {
		s.cfg.Scopes[scope] = description
	}
}

// ScopeDescription returns what to show a user for a scope.
func (s *Server) ScopeDescription(scope string) (string, bool) {
	description, ok := s.cfg.Scopes[scope]
	return description, ok
}

// validateScopes checks a request against the registry and the client.
func (s *Server) validateScopes(client *Client, requested Scopes) (Scopes, error) {
	if len(requested) == 0 {
		// An empty request means the client's own scopes, or nothing.
		return client.Scopes, nil
	}

	for _, scope := range requested {
		if scope == Wildcard {
			// Passport lets any client ask for everything. A third-party
			// application that can is one whose consent screen is a lie.
			if !client.FirstParty {
				return nil, errorf(ErrCodeInvalidScope,
					fmt.Sprintf("the scope %q is only available to first-party clients", Wildcard))
			}
			continue
		}
		if _, registered := s.cfg.Scopes[scope]; !registered {
			return nil, errorf(ErrCodeInvalidScope, fmt.Sprintf("unknown scope %q", scope))
		}
		if len(client.Scopes) > 0 && !client.Scopes.Has(scope) {
			return nil, errorf(ErrCodeInvalidScope,
				fmt.Sprintf("this client is not registered for the scope %q", scope))
		}
	}
	return requested, nil
}
