package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
)

// Keyring holds the key tokens are signed with and every key still trusted
// for verification.
//
// Rotation works by moving the active key aside and generating a new one.
// Tokens signed by the old key keep verifying until they expire, because its
// public half stays in the ring and in the JWKS.
type Keyring struct {
	signer    *rsa.PrivateKey
	signerKID string
	public    map[string]*rsa.PublicKey
	order     []string // signer first, then retired, for a stable JWKS
}

// Sign returns the active private key and its kid.
func (k *Keyring) Sign() (*rsa.PrivateKey, string) { return k.signer, k.signerKID }

// PublicKey returns the verification key for a kid.
//
// A miss is a miss. There is deliberately no "try every key" fallback: that
// would turn an unknown kid into a silent success and make rotation
// impossible to test.
func (k *Keyring) PublicKey(kid string) (*rsa.PublicKey, bool) {
	key, ok := k.public[kid]
	return key, ok
}

// KeySource yields the keys the server signs and verifies with. The first is
// the active signer; the rest verify only.
type KeySource interface {
	Load() ([]*rsa.PrivateKey, error)
}

// FileKeySource reads keys from a directory: private.key is the active
// signer, and retired/*.key are kept for verification.
type FileKeySource struct {
	Dir string

	// AllowInsecurePermissions skips the mode check. Only a test should set
	// it; a key others can read is a key you have to assume is compromised.
	AllowInsecurePermissions bool
}

const (
	privateKeyName = "private.key"
	publicKeyName  = "public.key"
	retiredDirName = "retired"
)

// PrivateKeyPath is where the active signer lives under dir.
func PrivateKeyPath(dir string) string { return filepath.Join(dir, privateKeyName) }

// PublicKeyPath is where the active signer's public half lives under dir.
func PublicKeyPath(dir string) string { return filepath.Join(dir, publicKeyName) }

// RetiredKeyPath is where a rotated-out key is kept.
func RetiredKeyPath(dir, kid string) string {
	// The kid is a base64url thumbprint, so it is filename-safe by
	// construction — but it is still sanitised, because a value that becomes
	// a path should never be trusted to be what it is supposed to be.
	return filepath.Join(dir, retiredDirName, sanitiseKID(kid)+".key")
}

func sanitiseKID(kid string) string {
	out := make([]rune, 0, len(kid))
	for _, r := range kid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		}
	}
	return string(out)
}

func (s FileKeySource) Load() ([]*rsa.PrivateKey, error) {
	active, err := s.readKey(PrivateKeyPath(s.Dir))
	if err != nil {
		return nil, err
	}
	keys := []*rsa.PrivateKey{active}

	entries, err := os.ReadDir(filepath.Join(s.Dir, retiredDirName))
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}
	// Sorted so the JWKS is stable between restarts and an ETag means
	// something.
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".key" {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		key, err := s.readKey(filepath.Join(s.Dir, retiredDirName, name))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (s FileKeySource) readKey(path string) (*rsa.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("oauth2: no signing key at %s; run `lemmego run oauth:keys` to generate one", path)
		}
		return nil, err
	}
	if !s.AllowInsecurePermissions && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("oauth2: %s is mode %04o; a signing key must not be readable by group or other (chmod 600)",
			path, info.Mode().Perm())
	}

	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(encoded)
}

// StaticKeySource serves keys held in memory, for tests and for a deployment
// that injects them another way.
type StaticKeySource struct{ Keys []*rsa.PrivateKey }

func (s StaticKeySource) Load() ([]*rsa.PrivateKey, error) {
	if len(s.Keys) == 0 {
		return nil, fmt.Errorf("oauth2: no signing key")
	}
	return s.Keys, nil
}

// EnvKeySource reads PEM straight from configuration, for a container with a
// read-only filesystem.
type EnvKeySource struct {
	Private string
	Retired []string
}

func (s EnvKeySource) Load() ([]*rsa.PrivateKey, error) {
	if s.Private == "" {
		return nil, fmt.Errorf("oauth2: no signing key configured")
	}
	active, err := ParsePrivateKey([]byte(s.Private))
	if err != nil {
		return nil, err
	}
	keys := []*rsa.PrivateKey{active}
	for _, encoded := range s.Retired {
		key, err := ParsePrivateKey([]byte(encoded))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// NewKeyring builds a ring from a source.
func NewKeyring(source KeySource) (*Keyring, error) {
	keys, err := source.Load()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("oauth2: no signing key")
	}

	ring := &Keyring{public: map[string]*rsa.PublicKey{}}
	for i, key := range keys {
		if key.N.BitLen() < 2048 {
			return nil, fmt.Errorf("oauth2: a %d-bit RSA key is too small; 2048 is the minimum", key.N.BitLen())
		}
		kid := KeyID(&key.PublicKey)
		if _, seen := ring.public[kid]; seen {
			continue
		}
		ring.public[kid] = &key.PublicKey
		ring.order = append(ring.order, kid)
		if i == 0 {
			ring.signer, ring.signerKID = key, kid
		}
	}
	return ring, nil
}

// KeyID is the RFC 7638 JWK thumbprint: SHA-256 over the canonical JSON of
// the key's required members, in lexicographic order, with no whitespace,
// base64url encoded without padding.
//
// Deriving the kid from the key rather than naming it has two consequences
// that matter. The same key always has the same kid, in every process, with
// no state to keep in sync. And a kid is never a path, a filename or a
// database key — only a lookup into a map built from keys already loaded — so
// a token claiming `"kid": "../../etc/passwd"` resolves to nothing and is
// rejected before anything touches a filesystem.
func KeyID(pub *rsa.PublicKey) string {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	sum := sha256.Sum256([]byte(`{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateKey returns a new RSA private key.
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	if bits < 2048 {
		return nil, fmt.Errorf("oauth2: refusing to generate a %d-bit key; 2048 is the minimum", bits)
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// EncodePrivateKey renders a key as PKCS#8 PEM.
func EncodePrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKey renders the public half as PKIX PEM.
func EncodePublicKey(key *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivateKey reads a PKCS#8 or PKCS#1 PEM key.
func ParsePrivateKey(encoded []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, fmt.Errorf("oauth2: not a PEM key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("oauth2: the key is %T, not RSA", key)
		}
		return rsaKey, nil
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot read the key: %w", err)
	}
	return key, nil
}

// WriteKey writes a private key and its public half under dir.
//
// O_EXCL is the point: a second run must fail rather than overwrite, because
// replacing the signer invalidates every access token in flight and every
// refresh token ever issued.
func WriteKey(dir string, key *rsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	private, err := EncodePrivateKey(key)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(PrivateKeyPath(dir), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("oauth2: %s already exists; replacing it would invalidate every token already issued",
				PrivateKeyPath(dir))
		}
		return err
	}
	if _, err := file.Write(private); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	public, err := EncodePublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(PublicKeyPath(dir), public, 0o644)
}

// RetireKey moves the active key aside so a new one can take its place. The
// retired key keeps verifying its outstanding tokens until they expire.
func RetireKey(dir string) (string, error) {
	encoded, err := os.ReadFile(PrivateKeyPath(dir))
	if err != nil {
		return "", err
	}
	key, err := ParsePrivateKey(encoded)
	if err != nil {
		return "", err
	}
	kid := KeyID(&key.PublicKey)

	if err := os.MkdirAll(filepath.Join(dir, retiredDirName), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(RetiredKeyPath(dir, kid), encoded, 0o600); err != nil {
		return "", err
	}
	if err := os.Remove(PrivateKeyPath(dir)); err != nil {
		return "", err
	}
	_ = os.Remove(PublicKeyPath(dir))
	return kid, nil
}

// JWKS is the public key set served at the discovery endpoint.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is one public key. Only the public members are present: there is no
// field here that could carry a private component even by accident.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS renders the ring as a key set, active key first.
func (k *Keyring) JWKS() JWKS {
	out := JWKS{Keys: make([]JWK, 0, len(k.order))}
	for _, kid := range k.order {
		key := k.public[kid]
		out.Keys = append(out.Keys, JWK{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		})
	}
	return out
}

// MarshalJWKS renders the key set as the JSON served at the JWKS endpoint.
func (k *Keyring) MarshalJWKS() ([]byte, error) { return json.Marshal(k.JWKS()) }

// keyringHolder swaps a ring atomically, so a reload does not tear.
type keyringHolder struct{ value atomic.Pointer[Keyring] }

func (h *keyringHolder) Load() *Keyring   { return h.value.Load() }
func (h *keyringHolder) Store(k *Keyring) { h.value.Store(k) }

func logKeyring(ring *Keyring) {
	slog.Info("oauth2: signing keys loaded", "kid", ring.signerKID, "verifying", len(ring.public))
}
