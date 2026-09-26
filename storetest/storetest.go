// Package storetest holds the contract every oauth2.Store must satisfy.
//
// Two implementations exist — an in-memory one the adversarial suite runs
// against for speed, and a database/sql one applications actually use — and
// the security properties live in the transitions, not in the callers. A
// single-use latch that holds under a mutex but not under concurrent SQL
// would mean the fast suite proves nothing. So both run this.
package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lemmego/oauth2"
)

// Factory returns a fresh, empty store. Each check gets its own.
type Factory func(t *testing.T) oauth2.Store

// Run executes the whole contract.
func Run(t *testing.T, newStore Factory) {
	t.Helper()
	for _, c := range []struct {
		name string
		run  func(*testing.T, Factory)
	}{
		{"ClientRoundTrip", clientRoundTrip},
		{"RevokeClientCascades", revokeClientCascades},
		{"AuthCodeIsSingleUse", authCodeIsSingleUse},
		{"AuthCodeExchangeIsAtomic", authCodeExchangeIsAtomic},
		{"AuthCodeExpires", authCodeExpires},
		{"RefreshRotates", refreshRotates},
		{"RefreshReuseIsDetected", refreshReuseIsDetected},
		{"RefreshRotationIsAtomic", refreshRotationIsAtomic},
		{"RevokeFamilyKillsTheChain", revokeFamilyKillsTheChain},
		{"AccessTokenRevocation", accessTokenRevocation},
		{"DeviceCodeApproval", deviceCodeApproval},
		{"DeviceCodeDenial", deviceCodeDenial},
		{"DevicePollEnforcesInterval", devicePollEnforcesInterval},
		{"DeviceCodeIsSingleUse", deviceCodeIsSingleUse},
		{"DeviceUserCodeIsUnique", deviceUserCodeIsUnique},
		{"TimestampsRoundTripInUTC", timestampsRoundTripInUTC},
		{"PruneRemovesOnlyExpired", pruneRemovesOnlyExpired},
		{"MissingRowsReportNotFound", missingRowsReportNotFound},
		{"IssuingADuplicateIDFails", issuingADuplicateIDFails},
	} {
		t.Run(c.name, func(t *testing.T) { c.run(t, newStore) })
	}
}

var base = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func ctx() context.Context { return context.Background() }

func client(id string) *oauth2.Client {
	return &oauth2.Client{
		ID: id, Name: "Test " + id, UserID: "owner-1",
		SecretHash:   "deadbeef",
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{oauth2.GrantAuthorizationCode, oauth2.GrantRefreshToken},
		Scopes:       oauth2.Scopes{"read", "write"},
		Confidential: true,
		CreatedAt:    base, UpdatedAt: base,
	}
}

func accessToken(id, family string) *oauth2.AccessToken {
	return &oauth2.AccessToken{
		ID: id, UserID: "user-1", ClientID: "client-1",
		Scopes: oauth2.Scopes{"read"}, FamilyID: family,
		ExpiresAt: base.Add(time.Hour), CreatedAt: base, UpdatedAt: base,
	}
}

func refreshToken(id, family, accessID string) *oauth2.RefreshToken {
	return &oauth2.RefreshToken{
		ID: id, AccessTokenID: accessID, ClientID: "client-1", UserID: "user-1",
		Scopes: oauth2.Scopes{"read"}, FamilyID: family,
		ExpiresAt: base.Add(14 * 24 * time.Hour), CreatedAt: base,
	}
}

func authCode(id, family string) *oauth2.AuthCode {
	return &oauth2.AuthCode{
		ID: id, UserID: "user-1", ClientID: "client-1",
		Scopes: oauth2.Scopes{"read"}, RedirectURI: "https://app.example.com/cb",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256",
		FamilyID: family, ExpiresAt: base.Add(time.Minute), CreatedAt: base,
	}
}

func deviceCode(id, userCodeHash, family string) *oauth2.DeviceCode {
	return &oauth2.DeviceCode{
		ID: id, UserCodeHash: userCodeHash, ClientID: "client-1",
		Scopes: oauth2.Scopes{"read"}, FamilyID: family,
		IntervalSeconds: 5, ExpiresAt: base.Add(10 * time.Minute), CreatedAt: base,
	}
}

func issue(accessID, refreshID, family string) oauth2.Issued {
	out := oauth2.Issued{Access: accessToken(accessID, family)}
	if refreshID != "" {
		out.Refresh = refreshToken(refreshID, family, accessID)
	}
	return out
}

func mustCreateClient(t *testing.T, s oauth2.Store) {
	t.Helper()
	if err := s.CreateClient(ctx(), client("client-1")); err != nil {
		t.Fatal(err)
	}
}

func clientRoundTrip(t *testing.T, newStore Factory) {
	s := newStore(t)
	want := client("client-1")
	if err := s.CreateClient(ctx(), want); err != nil {
		t.Fatal(err)
	}

	got, err := s.Client(ctx(), "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != want.Name || got.UserID != want.UserID || got.SecretHash != want.SecretHash {
		t.Errorf("client = %+v", got)
	}
	if !got.Scopes.Equal(want.Scopes) {
		t.Errorf("scopes = %v, want %v", got.Scopes, want.Scopes)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != want.RedirectURIs[0] {
		t.Errorf("redirect uris = %v", got.RedirectURIs)
	}
	if !got.Confidential {
		t.Error("confidential was not preserved; a confidential client must not decay into a public one")
	}
	if !got.AllowsGrant(oauth2.GrantAuthorizationCode) {
		t.Errorf("grant types = %v", got.GrantTypes)
	}

	// A duplicate id is a bug, not an upsert.
	if err := s.CreateClient(ctx(), client("client-1")); !errors.Is(err, oauth2.ErrDuplicate) {
		t.Errorf("duplicate CreateClient = %v, want ErrDuplicate", err)
	}

	owned, err := s.ClientsForUser(ctx(), "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 {
		t.Errorf("ClientsForUser returned %d clients, want 1", len(owned))
	}
}

// Revoking a client must kill its tokens at revoke time, so the cost is paid
// once by an administrator instead of by every request thereafter.
func revokeClientCascades(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAccessToken(ctx(), accessToken("jti-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeClient(ctx(), "client-1", base); err != nil {
		t.Fatal(err)
	}

	got, err := s.Client(ctx(), "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Error("the client is not revoked")
	}
	token, err := s.AccessToken(ctx(), "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	if !token.Revoked {
		t.Error("revoking the client left its access token live")
	}
}

func authCodeIsSingleUse(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAuthCode(ctx(), authCode("code-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	code, err := s.ExchangeAuthCode(ctx(), "code-1", issue("jti-1", "rt-1", "fam-1"), base)
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if code.ClientID != "client-1" || !code.Scopes.Equal(oauth2.Scopes{"read"}) {
		t.Errorf("exchanged code = %+v", code)
	}
	if code.CodeChallenge != "challenge" || code.CodeChallengeMethod != "S256" {
		t.Errorf("PKCE fields were not preserved: %+v", code)
	}
	if code.RedirectURI != "https://app.example.com/cb" {
		t.Errorf("redirect uri = %q", code.RedirectURI)
	}

	// The replay must be distinguishable from a code that never existed,
	// because a replay additionally has to revoke the family.
	_, err = s.ExchangeAuthCode(ctx(), "code-1", issue("jti-2", "rt-2", "fam-1"), base)
	if !errors.Is(err, oauth2.ErrCodeReplayed) {
		t.Fatalf("replay = %v, want ErrCodeReplayed", err)
	}
	if _, err := s.AccessToken(ctx(), "jti-2"); !errors.Is(err, oauth2.ErrNotFound) {
		t.Error("a replayed exchange issued a token")
	}
}

// Two requests carrying the same code must not both succeed. This is the
// property a read-then-write implementation gets wrong and a conditional
// update gets right.
func authCodeExchangeIsAtomic(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAuthCode(ctx(), authCode("code-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	const racers = 24
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.ExchangeAuthCode(ctx(), "code-1", issue(
				"jti-"+itoa(i), "rt-"+itoa(i), "fam-1"), base)
			if err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent exchanges succeeded, want exactly 1", succeeded, racers)
	}
}

func authCodeExpires(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAuthCode(ctx(), authCode("code-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	_, err := s.ExchangeAuthCode(ctx(), "code-1", issue("jti-1", "rt-1", "fam-1"), base.Add(time.Hour))
	if !errors.Is(err, oauth2.ErrExpired) {
		t.Fatalf("expired exchange = %v, want ErrExpired", err)
	}
	if _, err := s.AccessToken(ctx(), "jti-1"); !errors.Is(err, oauth2.ErrNotFound) {
		t.Error("an expired exchange issued a token")
	}
}

func refreshRotates(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAccessToken(ctx(), accessToken("jti-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	if err := seedRefresh(s, refreshToken("rt-1", "fam-1", "jti-1")); err != nil {
		t.Fatal(err)
	}

	old, err := s.RotateRefresh(ctx(), "rt-1", issue("jti-2", "rt-2", "fam-1"), base)
	if err != nil {
		t.Fatal(err)
	}
	if old.ClientID != "client-1" || old.UserID != "user-1" {
		t.Errorf("rotated token = %+v", old)
	}

	stale, err := s.RefreshToken(ctx(), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	if !stale.Revoked {
		t.Error("the rotated token is still live")
	}
	if stale.RotatedTo != "rt-2" {
		t.Errorf("rotated_to = %q, want %q", stale.RotatedTo, "rt-2")
	}
	if _, err := s.RefreshToken(ctx(), "rt-2"); err != nil {
		t.Errorf("the successor was not written: %v", err)
	}
}

func refreshReuseIsDetected(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := seedRefresh(s, refreshToken("rt-1", "fam-1", "jti-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateRefresh(ctx(), "rt-1", issue("jti-2", "rt-2", "fam-1"), base); err != nil {
		t.Fatal(err)
	}

	_, err := s.RotateRefresh(ctx(), "rt-1", issue("jti-3", "rt-3", "fam-1"), base)
	if !errors.Is(err, oauth2.ErrRefreshReused) {
		t.Fatalf("reuse = %v, want ErrRefreshReused", err)
	}
	if _, err := s.RefreshToken(ctx(), "rt-3"); !errors.Is(err, oauth2.ErrNotFound) {
		t.Error("a reused rotation issued a token")
	}
}

func refreshRotationIsAtomic(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := seedRefresh(s, refreshToken("rt-1", "fam-1", "jti-1")); err != nil {
		t.Fatal(err)
	}

	const racers = 24
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.RotateRefresh(ctx(), "rt-1", issue(
				"jti-"+itoa(i), "rt-new-"+itoa(i), "fam-1"), base); err == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d of %d concurrent rotations succeeded, want exactly 1", succeeded, racers)
	}
}

// One indexed update per table must kill everything descended from a grant,
// including the successor an honest client is still holding.
func revokeFamilyKillsTheChain(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	for _, id := range []string{"jti-1", "jti-2"} {
		if err := s.CreateAccessToken(ctx(), accessToken(id, "fam-1")); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.CreateAccessToken(ctx(), accessToken("jti-other", "fam-2")); err != nil {
		t.Fatal(err)
	}
	if err := seedRefresh(s, refreshToken("rt-1", "fam-1", "jti-1")); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeFamily(ctx(), "fam-1", base); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"jti-1", "jti-2"} {
		token, err := s.AccessToken(ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !token.Revoked {
			t.Errorf("%s survived the family revocation", id)
		}
	}
	stale, err := s.RefreshToken(ctx(), "rt-1")
	if err != nil {
		t.Fatal(err)
	}
	if !stale.Revoked {
		t.Error("the family's refresh token survived")
	}

	// An unrelated grant must be untouched, or revocation is a denial of
	// service rather than a containment.
	other, err := s.AccessToken(ctx(), "jti-other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Revoked {
		t.Error("revoking one family revoked another")
	}
}

func accessTokenRevocation(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAccessToken(ctx(), accessToken("jti-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessToken(ctx(), accessToken("jti-2", "fam-2")); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeAccessToken(ctx(), "jti-1", base); err != nil {
		t.Fatal(err)
	}
	token, err := s.AccessToken(ctx(), "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	if !token.Revoked {
		t.Error("the token is not revoked")
	}

	owned, err := s.AccessTokensForUser(ctx(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(owned) != 2 {
		t.Errorf("AccessTokensForUser returned %d, want 2", len(owned))
	}

	if err := s.RevokeForUserClient(ctx(), "user-1", "client-1", base); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"jti-1", "jti-2"} {
		token, err := s.AccessToken(ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !token.Revoked {
			t.Errorf("%s survived disconnecting the application", id)
		}
	}
}

func deviceCodeApproval(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateDeviceCode(ctx(), deviceCode("dev-1", "usercode-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	found, err := s.DeviceCodeByUserCode(ctx(), "usercode-1")
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != "dev-1" {
		t.Fatalf("lookup by user code returned %q", found.ID)
	}

	// Polling before approval must say pending, not fail.
	if _, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base); err != nil || outcome != oauth2.PollPending {
		t.Fatalf("poll before approval = %v, %v", outcome, err)
	}

	// The user may narrow what was asked for.
	if err := s.ApproveDeviceCode(ctx(), "usercode-1", "user-9", oauth2.Scopes{"read"}, base); err != nil {
		t.Fatal(err)
	}

	// A second decision must not overwrite the first.
	if err := s.ApproveDeviceCode(ctx(), "usercode-1", "attacker", oauth2.Scopes{"write"}, base); !errors.Is(err, oauth2.ErrAlreadyDecided) {
		t.Errorf("second approval = %v, want ErrAlreadyDecided", err)
	}

	device, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != oauth2.PollReady {
		t.Fatalf("poll after approval = %v, want PollReady", outcome)
	}
	if device.UserID != "user-9" {
		t.Errorf("approved user = %q", device.UserID)
	}
}

func deviceCodeDenial(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateDeviceCode(ctx(), deviceCode("dev-1", "usercode-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.DenyDeviceCode(ctx(), "usercode-1", base); err != nil {
		t.Fatal(err)
	}

	_, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != oauth2.PollDenied {
		t.Fatalf("poll after denial = %v, want PollDenied", outcome)
	}
	if _, err := s.ExchangeDeviceCode(ctx(), "dev-1", issue("jti-1", "", "fam-1"), base); err == nil {
		t.Error("a denied device code was exchanged for a token")
	}
}

// RFC 8628 section 3.5: a device polling faster than the interval is told to
// slow down, and the interval grows by five seconds each time.
func devicePollEnforcesInterval(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateDeviceCode(ctx(), deviceCode("dev-1", "usercode-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	if _, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base); err != nil || outcome != oauth2.PollPending {
		t.Fatalf("first poll = %v, %v", outcome, err)
	}

	device, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != oauth2.PollSlowDown {
		t.Fatalf("early poll = %v, want PollSlowDown", outcome)
	}
	if device.IntervalSeconds != 10 {
		t.Errorf("interval = %d, want 10", device.IntervalSeconds)
	}

	// Still too early, now against the raised interval.
	if _, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base.Add(6*time.Second)); err != nil || outcome != oauth2.PollSlowDown {
		t.Fatalf("poll inside the raised interval = %v, %v", outcome, err)
	}

	// Waiting long enough is allowed again.
	if _, outcome, err := s.PollDeviceCode(ctx(), "dev-1", base.Add(time.Minute)); err != nil || outcome != oauth2.PollPending {
		t.Fatalf("poll after waiting = %v, %v", outcome, err)
	}
}

func deviceCodeIsSingleUse(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateDeviceCode(ctx(), deviceCode("dev-1", "usercode-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveDeviceCode(ctx(), "usercode-1", "user-9", oauth2.Scopes{"read"}, base); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ExchangeDeviceCode(ctx(), "dev-1", issue("jti-1", "rt-1", "fam-1"), base); err != nil {
		t.Fatal(err)
	}
	_, err := s.ExchangeDeviceCode(ctx(), "dev-1", issue("jti-2", "rt-2", "fam-1"), base)
	if !errors.Is(err, oauth2.ErrCodeReplayed) {
		t.Fatalf("second exchange = %v, want ErrCodeReplayed", err)
	}
	if _, err := s.AccessToken(ctx(), "jti-2"); !errors.Is(err, oauth2.ErrNotFound) {
		t.Error("a replayed device exchange issued a token")
	}
}

// Issuing must not mint a duplicate user code and leave two devices waiting
// on one entry.
func deviceUserCodeIsUnique(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateDeviceCode(ctx(), deviceCode("dev-1", "usercode-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	err := s.CreateDeviceCode(ctx(), deviceCode("dev-2", "usercode-1", "fam-2"))
	if !errors.Is(err, oauth2.ErrDuplicate) {
		t.Fatalf("duplicate user code = %v, want ErrDuplicate", err)
	}
}

// SQLite hands back a DATETIME(6) column as text and MySQL needs parseTime in
// its DSN, so a store that scans straight into time.Time works on one
// database and not another. Expiry is the whole security model here, so the
// round trip is pinned to the microsecond and to UTC.
func timestampsRoundTripInUTC(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)

	precise := time.Date(2026, 9, 26, 12, 34, 56, 123456000, time.UTC)
	token := accessToken("jti-1", "fam-1")
	token.ExpiresAt = precise
	token.CreatedAt = precise
	if err := s.CreateAccessToken(ctx(), token); err != nil {
		t.Fatal(err)
	}

	got, err := s.AccessToken(ctx(), "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(precise) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, precise)
	}
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("expires_at came back in %v, want UTC", got.ExpiresAt.Location())
	}

	// A local-zone write must come back as the same instant, or a server in
	// a non-UTC zone silently shifts every expiry.
	local := precise.In(time.FixedZone("test", 5*3600))
	shifted := accessToken("jti-2", "fam-1")
	shifted.ExpiresAt = local
	if err := s.CreateAccessToken(ctx(), shifted); err != nil {
		t.Fatal(err)
	}
	back, err := s.AccessToken(ctx(), "jti-2")
	if err != nil {
		t.Fatal(err)
	}
	if !back.ExpiresAt.Equal(precise) {
		t.Errorf("a non-UTC write came back as %v, want the same instant as %v", back.ExpiresAt, precise)
	}
}

func pruneRemovesOnlyExpired(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)

	stale := accessToken("jti-old", "fam-1")
	stale.ExpiresAt = base.Add(-time.Hour)
	if err := s.CreateAccessToken(ctx(), stale); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccessToken(ctx(), accessToken("jti-live", "fam-1")); err != nil {
		t.Fatal(err)
	}

	result, err := s.Prune(ctx(), base)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessTokens != 1 {
		t.Errorf("pruned %d access tokens, want 1", result.AccessTokens)
	}
	if _, err := s.AccessToken(ctx(), "jti-old"); !errors.Is(err, oauth2.ErrNotFound) {
		t.Error("the expired token survived pruning")
	}
	if _, err := s.AccessToken(ctx(), "jti-live"); err != nil {
		t.Errorf("pruning removed a live token: %v", err)
	}
}

// Every read must distinguish absence from failure, because the hot path
// fails closed on absence and must not fail closed on a dropped connection.
func missingRowsReportNotFound(t *testing.T, newStore Factory) {
	s := newStore(t)
	for name, err := range map[string]error{
		"Client":               second(s.Client(ctx(), "nope")),
		"AccessToken":          second(s.AccessToken(ctx(), "nope")),
		"RefreshToken":         second(s.RefreshToken(ctx(), "nope")),
		"DeviceCodeByUserCode": second(s.DeviceCodeByUserCode(ctx(), "nope")),
	} {
		if !errors.Is(err, oauth2.ErrNotFound) {
			t.Errorf("%s on a missing row = %v, want ErrNotFound", name, err)
		}
	}
	if err := s.RevokeAccessToken(ctx(), "nope", base); !errors.Is(err, oauth2.ErrNotFound) {
		t.Errorf("RevokeAccessToken on a missing row = %v, want ErrNotFound", err)
	}
	if _, err := s.ExchangeAuthCode(ctx(), "nope", issue("jti-1", "", "fam-1"), base); !errors.Is(err, oauth2.ErrNotFound) {
		t.Errorf("ExchangeAuthCode on a missing row = %v, want ErrNotFound", err)
	}
}

// issuingADuplicateIDFails pins the two stores to the same answer. The SQL
// store gets this from a unique constraint; the memory store has to be
// written to match, and without a check here it could silently accept a state
// the real store refuses — which would make every other check in this suite
// prove less than it appears to.
func issuingADuplicateIDFails(t *testing.T, newStore Factory) {
	s := newStore(t)
	mustCreateClient(t, s)
	if err := s.CreateAccessToken(ctx(), accessToken("jti-1", "fam-1")); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAuthCode(ctx(), authCode("code-1", "fam-1")); err != nil {
		t.Fatal(err)
	}

	// The exchange tries to issue an access token whose id is already taken.
	_, err := s.ExchangeAuthCode(ctx(), "code-1", issue("jti-1", "rt-1", "fam-1"), base)
	if !errors.Is(err, oauth2.ErrDuplicate) {
		t.Fatalf("issuing a duplicate token id = %v, want ErrDuplicate", err)
	}

	// And the code must not have been consumed by the failed attempt, or a
	// collision would burn a code that was never exchanged.
	if _, err := s.ExchangeAuthCode(ctx(), "code-1", issue("jti-2", "rt-2", "fam-1"), base); err != nil {
		t.Fatalf("the code was consumed by a failed exchange: %v", err)
	}
}
