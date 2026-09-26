package oauth2

import (
	"fmt"
	"strings"
	"time"

	"github.com/lemmego/api/config"
)

// RevocationMode says how much work each authenticated request does to find
// out whether a token has been revoked.
type RevocationMode string

const (
	// RevocationAlways reads the token's row on every request. One indexed
	// primary-key lookup, and the only setting under which revoking a token
	// takes effect immediately.
	RevocationAlways RevocationMode = "always"

	// RevocationCached remembers that a token was live for a short while.
	// It reopens a revocation window exactly as long as that TTL.
	RevocationCached RevocationMode = "cached"

	// RevocationNever trusts the signature alone. Revoking a token then does
	// nothing until it expires; the only reason to choose this is a resource
	// server that cannot reach the database at all.
	RevocationNever RevocationMode = "never"
)

// Config is the resolved configuration.
type Config struct {
	RoutePrefix string
	Issuer      string
	Audience    string

	KeysPath  string
	KeyLength int

	AccessTokenTTL   time.Duration
	RefreshTokenTTL  time.Duration
	AuthCodeTTL      time.Duration
	DeviceCodeTTL    time.Duration
	PersonalTokenTTL time.Duration

	RequirePKCE      bool
	RefreshRotation  bool
	ReuseGracePeriod time.Duration
	Revocation       RevocationMode

	SkipConsentForFirstParty bool
	LoginRoute               string

	// ManagementRoutes mounts the page where a signed-in user registers and
	// revokes their own clients. It lists only their own, so it needs no
	// administrator role — but an application that registers clients another
	// way, or shows them in its own interface, can turn it off.
	ManagementRoutes bool

	// Scopes maps a scope to the description shown on the consent screen. A
	// scope absent from here is rejected rather than silently dropped, which
	// is what stops a client believing it has access it was never granted.
	Scopes map[string]string

	CORSOrigins     []string
	PruneAfterHours int
	TablePrefix     string

	// DeviceInterval is the minimum gap between device polls, in seconds.
	DeviceInterval int
}

// DefaultConfig is what an application gets before it configures anything.
func DefaultConfig() *Config {
	return &Config{
		RoutePrefix:              "/oauth",
		KeysPath:                 "./storage/oauth",
		KeyLength:                2048,
		AccessTokenTTL:           time.Hour,
		RefreshTokenTTL:          14 * 24 * time.Hour,
		AuthCodeTTL:              60 * time.Second,
		DeviceCodeTTL:            10 * time.Minute,
		PersonalTokenTTL:         365 * 24 * time.Hour,
		RequirePKCE:              true,
		RefreshRotation:          true,
		ReuseGracePeriod:         0,
		Revocation:               RevocationAlways,
		SkipConsentForFirstParty: true,
		LoginRoute:               "/login",
		ManagementRoutes:         true,
		Scopes:                   map[string]string{},
		PruneAfterHours:          168,
		TablePrefix:              "oauth_",
		DeviceInterval:           5,
	}
}

// resolveConfig layers the published configuration over the defaults.
func resolveConfig(explicit *Config, section config.M) (*Config, error) {
	cfg := DefaultConfig()
	if explicit != nil {
		merged := *explicit
		applyDefaultsTo(&merged)
		cfg = &merged
	}
	if section != nil {
		if err := cfg.apply(section); err != nil {
			return nil, err
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyDefaultsTo fills the zero fields of a caller-supplied Config, so
// setting one option does not silently blank every other.
func applyDefaultsTo(cfg *Config) {
	defaults := DefaultConfig()
	if cfg.RoutePrefix == "" {
		cfg.RoutePrefix = defaults.RoutePrefix
	}
	if cfg.KeysPath == "" {
		cfg.KeysPath = defaults.KeysPath
	}
	if cfg.KeyLength == 0 {
		cfg.KeyLength = defaults.KeyLength
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = defaults.AccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = defaults.RefreshTokenTTL
	}
	if cfg.AuthCodeTTL == 0 {
		cfg.AuthCodeTTL = defaults.AuthCodeTTL
	}
	if cfg.DeviceCodeTTL == 0 {
		cfg.DeviceCodeTTL = defaults.DeviceCodeTTL
	}
	if cfg.PersonalTokenTTL == 0 {
		cfg.PersonalTokenTTL = defaults.PersonalTokenTTL
	}
	if cfg.Revocation == "" {
		cfg.Revocation = defaults.Revocation
	}
	if cfg.LoginRoute == "" {
		cfg.LoginRoute = defaults.LoginRoute
	}
	if cfg.Scopes == nil {
		cfg.Scopes = map[string]string{}
	}
	if cfg.PruneAfterHours == 0 {
		cfg.PruneAfterHours = defaults.PruneAfterHours
	}
	if cfg.TablePrefix == "" {
		cfg.TablePrefix = defaults.TablePrefix
	}
	if cfg.DeviceInterval == 0 {
		cfg.DeviceInterval = defaults.DeviceInterval
	}
}

func (cfg *Config) apply(section config.M) error {
	applyString(section, "route_prefix", &cfg.RoutePrefix)
	applyString(section, "issuer", &cfg.Issuer)
	applyString(section, "audience", &cfg.Audience)
	applyString(section, "login_route", &cfg.LoginRoute)
	applyString(section, "table_prefix", &cfg.TablePrefix)
	applyBool(section, "require_pkce", &cfg.RequirePKCE)
	applyBool(section, "refresh_rotation", &cfg.RefreshRotation)
	applyBool(section, "skip_consent_for_first_party", &cfg.SkipConsentForFirstParty)
	applyBool(section, "management_routes", &cfg.ManagementRoutes)
	applyInt(section, "prune_after_hours", &cfg.PruneAfterHours)

	if keys, ok := section["keys"].(config.M); ok {
		applyString(keys, "path", &cfg.KeysPath)
		applyInt(keys, "length", &cfg.KeyLength)
	}

	if ttl, ok := section["ttl"].(config.M); ok {
		for key, into := range map[string]*time.Duration{
			"access_token":   &cfg.AccessTokenTTL,
			"refresh_token":  &cfg.RefreshTokenTTL,
			"auth_code":      &cfg.AuthCodeTTL,
			"device_code":    &cfg.DeviceCodeTTL,
			"personal_token": &cfg.PersonalTokenTTL,
		} {
			if err := applyDuration(ttl, key, into); err != nil {
				return fmt.Errorf("oauth: ttl.%s: %w", key, err)
			}
		}
	}

	if err := applyDuration(section, "reuse_grace_period", &cfg.ReuseGracePeriod); err != nil {
		return fmt.Errorf("oauth: reuse_grace_period: %w", err)
	}

	if raw, ok := section["revocation"].(string); ok && raw != "" {
		mode := RevocationMode(strings.ToLower(strings.TrimSpace(raw)))
		switch mode {
		case RevocationAlways, RevocationCached, RevocationNever:
			cfg.Revocation = mode
		default:
			return fmt.Errorf("oauth: revocation is %q, want always, cached or never", raw)
		}
	}

	if scopes, ok := section["scopes"].(config.M); ok {
		if cfg.Scopes == nil {
			cfg.Scopes = map[string]string{}
		}
		for scope, description := range scopes {
			text, _ := description.(string)
			cfg.Scopes[scope] = text
		}
	}

	if raw, ok := section["cors_origins"].(string); ok {
		for _, origin := range strings.Split(raw, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, origin)
			}
		}
	}
	return nil
}

func applyString(section config.M, key string, into *string) {
	if value, ok := section[key].(string); ok && value != "" {
		*into = value
	}
}

func applyBool(section config.M, key string, into *bool) {
	if value, ok := section[key].(bool); ok {
		*into = value
	}
}

func applyInt(section config.M, key string, into *int) {
	if value, ok := section[key].(int); ok && value != 0 {
		*into = value
	}
}

// applyDuration accepts both a time.Duration and the string form a config
// stub writes, since MustEnv hands back whatever the fallback's type was.
func applyDuration(section config.M, key string, into *time.Duration) error {
	switch value := section[key].(type) {
	case time.Duration:
		*into = value
	case string:
		if strings.TrimSpace(value) == "" {
			return nil
		}
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%q is not a duration; use a unit, for example \"30m\" or \"24h\"", value)
		}
		*into = parsed
	case int:
		// A bare number is ambiguous and the mistake is easy to make, so say
		// so rather than guessing at seconds.
		return fmt.Errorf("%d has no unit; write it as a duration, for example \"%ds\"", value, value)
	}
	return nil
}

func (cfg *Config) validate() error {
	if !strings.HasPrefix(cfg.RoutePrefix, "/") {
		return fmt.Errorf("oauth: route_prefix %q must start with /", cfg.RoutePrefix)
	}
	// A prefix of "/" would put /authorize at the application's root and
	// collide with its own routes.
	if cfg.RoutePrefix == "/" {
		return fmt.Errorf("oauth: route_prefix must not be /; the endpoints need a prefix of their own")
	}
	cfg.RoutePrefix = strings.TrimRight(cfg.RoutePrefix, "/")

	if cfg.KeyLength < 2048 {
		return fmt.Errorf("oauth: keys.length is %d; RSA keys below 2048 bits are not accepted", cfg.KeyLength)
	}
	if !validTablePrefix(cfg.TablePrefix) {
		return fmt.Errorf("oauth: table_prefix %q must be letters, digits and underscores", cfg.TablePrefix)
	}
	if cfg.AccessTokenTTL <= 0 {
		return fmt.Errorf("oauth: ttl.access_token must be positive")
	}
	if cfg.AuthCodeTTL <= 0 {
		return fmt.Errorf("oauth: ttl.auth_code must be positive")
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.Issuer
	}
	return nil
}

// URL builds an absolute URL for a path under the route prefix, which is what
// the discovery document advertises.
func (cfg *Config) URL(path string) string {
	return strings.TrimRight(cfg.Issuer, "/") + cfg.RoutePrefix + path
}

// RootURL builds an absolute URL for a path at the site root, which is where
// RFC 8414 requires the discovery document and the JWKS to live.
func (cfg *Config) RootURL(path string) string {
	return strings.TrimRight(cfg.Issuer, "/") + path
}
