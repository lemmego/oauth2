package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

// A signing key that others can read is a key you have to assume is
// compromised, and replacing one invalidates every token ever issued — so
// both the mode and the refusal to overwrite are load-bearing.
func TestWriteKeyIsPrivateAndRefusesToOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oauth")

	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, key); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(PrivateKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key is mode %04o, want 0600", perm)
	}
	if dirInfo, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("key directory is mode %04o, want 0700", perm)
	}

	replacement, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, replacement); err == nil {
		t.Fatal("a second WriteKey replaced the signing key")
	}

	// And the original must still be there, unchanged.
	ring, err := NewKeyring(FileKeySource{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, kid := ring.Sign(); kid != KeyID(&key.PublicKey) {
		t.Error("the original key was replaced")
	}
}

// A world-readable key must be refused rather than used.
func TestLoadingRefusesALooseKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oauth")
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(PrivateKeyPath(dir), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := NewKeyring(FileKeySource{Dir: dir}); err == nil {
		t.Fatal("a group- and world-readable signing key was loaded")
	}
	// The escape hatch has to work, or a test cannot use a fixture.
	if _, err := NewKeyring(FileKeySource{Dir: dir, AllowInsecurePermissions: true}); err != nil {
		t.Fatalf("the explicit override did not work: %v", err)
	}
}

// Rotation must keep the retired key verifying, or every token issued before
// the rotation breaks the moment it happens.
func TestRotationKeepsVerifyingOldTokens(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oauth")
	first, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, first); err != nil {
		t.Fatal(err)
	}

	retired, err := RetireKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if retired != KeyID(&first.PublicKey) {
		t.Errorf("retired kid = %q", retired)
	}

	second, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteKey(dir, second); err != nil {
		t.Fatal(err)
	}

	ring, err := NewKeyring(FileKeySource{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, kid := ring.Sign(); kid != KeyID(&second.PublicKey) {
		t.Error("the new key is not the active signer")
	}
	if _, ok := ring.PublicKey(retired); !ok {
		t.Error("the retired key no longer verifies, so every token it signed is broken")
	}
	if len(ring.JWKS().Keys) != 2 {
		t.Errorf("the JWKS lists %d keys, want the active and the retired one", len(ring.JWKS().Keys))
	}
}

// A key too small to be safe must be refused at both ends: generating one and
// loading one someone else generated.
func TestSmallKeysAreRefused(t *testing.T) {
	if _, err := GenerateKey(1024); err == nil {
		t.Error("a 1024-bit key was generated")
	}

	// Generated directly, bypassing the floor GenerateKey enforces, so the
	// loading path is exercised on a key someone else produced.
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyring(StaticKeySource{Keys: []*rsa.PrivateKey{small}}); err == nil {
		t.Error("a 1024-bit key was loaded")
	}
}

// A scaffolded project already ignores storage/*, which covers the default
// key directory. Appending a second rule would be noise implying the first
// was not enough.
func TestGitignoreCoverageIsRecognised(t *testing.T) {
	const scaffolded = `
/node_modules
public/hot
public/storage
storage/*
!storage/.gitkeep
.env
`
	for _, tc := range []struct {
		path string
		want bool
		why  string
	}{
		{"storage/oauth", true, "storage/* covers it"},
		// storage/* matches what is inside storage, not storage itself, and
		// the fixture has no bare storage rule.
		{"storage", false, "storage/* covers the contents, not the directory"},
		{"node_modules", true, "a leading slash is not part of the name"},
		{"var/keys", false, "nothing mentions it"},
		{"storage/.gitkeep", true, "the negation re-includes it but storage/* still matches the parent"},
	} {
		if got := gitignoreCovers(scaffolded, tc.path); got != tc.want {
			t.Errorf("gitignoreCovers(%q) = %v, want %v (%s)", tc.path, got, tc.want, tc.why)
		}
	}

	// A negation alone must never count as coverage, or a key would be left
	// committed on the strength of a rule that re-includes it.
	if gitignoreCovers("!storage/oauth\n", "storage/oauth") {
		t.Error("a negation was treated as ignoring the path")
	}
}
