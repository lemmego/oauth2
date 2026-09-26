package oauth2

import (
	"context"
	"sync"
	"time"
)

// MemoryStore keeps protocol state in memory.
//
// It exists so the adversarial suite can run thousands of cases without a
// database, and so an application can try the server out before choosing
// where to persist it. It is not for production: every token dies with the
// process, and nothing is shared between them.
//
// The single mutex is what makes the transitions atomic here, standing in for
// the conditional UPDATE the SQL store uses. Both are verified by the same
// conformance suite, so a green run against this one means something.
type MemoryStore struct {
	mu sync.Mutex

	clients    map[string]*Client
	authCodes  map[string]*AuthCode
	access     map[string]*AccessToken
	refresh    map[string]*RefreshToken
	devices    map[string]*DeviceCode
	byUserCode map[string]string // user code hash -> device code id
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:    map[string]*Client{},
		authCodes:  map[string]*AuthCode{},
		access:     map[string]*AccessToken{},
		refresh:    map[string]*RefreshToken{},
		devices:    map[string]*DeviceCode{},
		byUserCode: map[string]string{},
	}
}

var _ Store = (*MemoryStore)(nil)

// Callers get copies. Handing out the stored pointer would let a caller
// mutate committed state without going through a transition, which is exactly
// the race the transitions exist to prevent — and the SQL store, which
// returns freshly scanned rows, would not behave the same way.

func cloneClient(c *Client) *Client {
	out := *c
	out.RedirectURIs = append([]string(nil), c.RedirectURIs...)
	out.GrantTypes = append([]string(nil), c.GrantTypes...)
	out.Scopes = append(Scopes(nil), c.Scopes...)
	return &out
}

func cloneAuthCode(c *AuthCode) *AuthCode {
	out := *c
	out.Scopes = append(Scopes(nil), c.Scopes...)
	return &out
}

func cloneAccess(t *AccessToken) *AccessToken {
	out := *t
	out.Scopes = append(Scopes(nil), t.Scopes...)
	return &out
}

func cloneRefresh(t *RefreshToken) *RefreshToken {
	out := *t
	out.Scopes = append(Scopes(nil), t.Scopes...)
	return &out
}

func cloneDevice(d *DeviceCode) *DeviceCode {
	out := *d
	out.Scopes = append(Scopes(nil), d.Scopes...)
	return &out
}

func (m *MemoryStore) Client(_ context.Context, id string) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneClient(client), nil
}

func (m *MemoryStore) CreateClient(_ context.Context, c *Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.clients[c.ID]; exists {
		return ErrDuplicate
	}
	m.clients[c.ID] = cloneClient(c)
	return nil
}

func (m *MemoryStore) UpdateClient(_ context.Context, c *Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[c.ID]; !ok {
		return ErrNotFound
	}
	m.clients[c.ID] = cloneClient(c)
	return nil
}

func (m *MemoryStore) ClientsForUser(_ context.Context, userID string) ([]*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Client
	for _, client := range m.clients {
		if client.UserID == userID {
			out = append(out, cloneClient(client))
		}
	}
	return out, nil
}

func (m *MemoryStore) RevokeClient(_ context.Context, id string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	client, ok := m.clients[id]
	if !ok {
		return ErrNotFound
	}
	client.Revoked = true
	client.UpdatedAt = now.UTC()
	// Cascade now so the hot path never has to ask whether the client behind
	// a token is still live.
	for _, token := range m.access {
		if token.ClientID == id {
			token.Revoked = true
			token.UpdatedAt = now.UTC()
		}
	}
	for _, token := range m.refresh {
		if token.ClientID == id {
			token.Revoked = true
		}
	}
	return nil
}

func (m *MemoryStore) CreateAuthCode(_ context.Context, code *AuthCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.authCodes[code.ID]; exists {
		return ErrDuplicate
	}
	m.authCodes[code.ID] = cloneAuthCode(code)
	return nil
}

func (m *MemoryStore) ExchangeAuthCode(_ context.Context, id string, issue Issued, now time.Time) (*AuthCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	code, ok := m.authCodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	if code.ConsumedAt != nil {
		return cloneAuthCode(code), ErrCodeReplayed
	}
	if code.Revoked {
		return cloneAuthCode(code), ErrNotFound
	}
	if !code.ExpiresAt.After(now) {
		return cloneAuthCode(code), ErrExpired
	}

	if err := m.putIssued(issue); err != nil {
		return cloneAuthCode(code), err
	}
	consumed := now.UTC()
	code.ConsumedAt = &consumed
	return cloneAuthCode(code), nil
}

// putIssued writes the pair a grant produced.
//
// A duplicate id is rejected rather than overwritten, matching the unique
// constraint the SQL store relies on. Silently replacing a token would make
// this store accept a state the real one refuses, and the conformance suite
// would then prove less than it appears to.
func (m *MemoryStore) putIssued(issue Issued) error {
	if issue.Access != nil {
		if _, exists := m.access[issue.Access.ID]; exists {
			return ErrDuplicate
		}
	}
	if issue.Refresh != nil {
		if _, exists := m.refresh[issue.Refresh.ID]; exists {
			return ErrDuplicate
		}
	}
	if issue.Access != nil {
		m.access[issue.Access.ID] = cloneAccess(issue.Access)
	}
	if issue.Refresh != nil {
		m.refresh[issue.Refresh.ID] = cloneRefresh(issue.Refresh)
	}
	return nil
}

func (m *MemoryStore) RefreshToken(_ context.Context, id string) (*RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.refresh[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneRefresh(token), nil
}

func (m *MemoryStore) RotateRefresh(_ context.Context, oldID string, issue Issued, now time.Time) (*RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, ok := m.refresh[oldID]
	if !ok {
		return nil, ErrNotFound
	}
	if token.Revoked || token.RotatedTo != "" {
		return cloneRefresh(token), ErrRefreshReused
	}
	if !token.ExpiresAt.After(now) {
		return cloneRefresh(token), ErrExpired
	}

	if err := m.putIssued(issue); err != nil {
		return cloneRefresh(token), err
	}
	token.Revoked = true
	if issue.Refresh != nil {
		token.RotatedTo = issue.Refresh.ID
	}
	return cloneRefresh(token), nil
}

func (m *MemoryStore) CreateAccessToken(_ context.Context, t *AccessToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.access[t.ID]; exists {
		return ErrDuplicate
	}
	m.access[t.ID] = cloneAccess(t)
	return nil
}

func (m *MemoryStore) AccessToken(_ context.Context, jti string) (*AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.access[jti]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneAccess(token), nil
}

func (m *MemoryStore) AccessTokensForUser(_ context.Context, userID string) ([]*AccessToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*AccessToken
	for _, token := range m.access {
		if token.UserID == userID {
			out = append(out, cloneAccess(token))
		}
	}
	return out, nil
}

func (m *MemoryStore) RevokeAccessToken(_ context.Context, jti string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, ok := m.access[jti]
	if !ok {
		return ErrNotFound
	}
	token.Revoked = true
	token.UpdatedAt = now.UTC()
	return nil
}

func (m *MemoryStore) RevokeFamily(_ context.Context, familyID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, token := range m.access {
		if token.FamilyID == familyID {
			token.Revoked = true
			token.UpdatedAt = now.UTC()
		}
	}
	for _, token := range m.refresh {
		if token.FamilyID == familyID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *MemoryStore) RevokeForUserClient(_ context.Context, userID, clientID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, token := range m.access {
		if token.UserID == userID && token.ClientID == clientID {
			token.Revoked = true
			token.UpdatedAt = now.UTC()
		}
	}
	for _, token := range m.refresh {
		if token.UserID == userID && token.ClientID == clientID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *MemoryStore) CreateDeviceCode(_ context.Context, d *DeviceCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.devices[d.ID]; exists {
		return ErrDuplicate
	}
	// The user code is unique so that issuing cannot mint a duplicate and
	// leave two devices waiting on one code.
	if _, exists := m.byUserCode[d.UserCodeHash]; exists {
		return ErrDuplicate
	}
	m.devices[d.ID] = cloneDevice(d)
	m.byUserCode[d.UserCodeHash] = d.ID
	return nil
}

func (m *MemoryStore) DeviceCodeByUserCode(_ context.Context, userCodeHash string) (*DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byUserCode[userCodeHash]
	if !ok {
		return nil, ErrNotFound
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneDevice(device), nil
}

func (m *MemoryStore) ApproveDeviceCode(_ context.Context, userCodeHash, userID string, scopes Scopes, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	device, err := m.deviceByUserCodeLocked(userCodeHash)
	if err != nil {
		return err
	}
	if device.ApprovedAt != nil || device.DeniedAt != nil {
		return ErrAlreadyDecided
	}
	if !device.ExpiresAt.After(now) {
		return ErrExpired
	}
	at := now.UTC()
	device.ApprovedAt = &at
	device.UserID = userID
	device.Scopes = append(Scopes(nil), scopes...)
	return nil
}

func (m *MemoryStore) DenyDeviceCode(_ context.Context, userCodeHash string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	device, err := m.deviceByUserCodeLocked(userCodeHash)
	if err != nil {
		return err
	}
	if device.ApprovedAt != nil || device.DeniedAt != nil {
		return ErrAlreadyDecided
	}
	at := now.UTC()
	device.DeniedAt = &at
	return nil
}

func (m *MemoryStore) deviceByUserCodeLocked(userCodeHash string) (*DeviceCode, error) {
	id, ok := m.byUserCode[userCodeHash]
	if !ok {
		return nil, ErrNotFound
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	return device, nil
}

func (m *MemoryStore) PollDeviceCode(_ context.Context, id string, now time.Time) (*DeviceCode, PollOutcome, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[id]
	if !ok {
		return nil, PollPending, ErrNotFound
	}

	// The interval check comes first and applies even to a finished
	// authorization, so a device cannot escape the rate limit by polling a
	// code it knows is ready.
	interval := time.Duration(device.IntervalSeconds) * time.Second
	if device.LastPolledAt != nil && now.Sub(*device.LastPolledAt) < interval {
		device.IntervalSeconds += 5
		at := now.UTC()
		device.LastPolledAt = &at
		device.PollCount++
		return cloneDevice(device), PollSlowDown, nil
	}

	at := now.UTC()
	device.LastPolledAt = &at
	device.PollCount++

	switch {
	case device.DeniedAt != nil:
		return cloneDevice(device), PollDenied, nil
	case !device.ExpiresAt.After(now):
		return cloneDevice(device), PollExpired, nil
	case device.ConsumedAt != nil:
		return cloneDevice(device), PollExpired, nil
	case device.ApprovedAt != nil:
		return cloneDevice(device), PollReady, nil
	default:
		return cloneDevice(device), PollPending, nil
	}
}

func (m *MemoryStore) ExchangeDeviceCode(_ context.Context, id string, issue Issued, now time.Time) (*DeviceCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[id]
	if !ok {
		return nil, ErrNotFound
	}
	if device.ConsumedAt != nil {
		return cloneDevice(device), ErrCodeReplayed
	}
	if device.ApprovedAt == nil {
		return cloneDevice(device), ErrNotApproved
	}
	if !device.ExpiresAt.After(now) {
		return cloneDevice(device), ErrExpired
	}

	if err := m.putIssued(issue); err != nil {
		return cloneDevice(device), err
	}
	consumed := now.UTC()
	device.ConsumedAt = &consumed
	return cloneDevice(device), nil
}

func (m *MemoryStore) Prune(_ context.Context, before time.Time) (PruneResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result PruneResult
	for id, code := range m.authCodes {
		if code.ExpiresAt.Before(before) {
			delete(m.authCodes, id)
			result.AuthCodes++
		}
	}
	for id, token := range m.access {
		if token.ExpiresAt.Before(before) {
			delete(m.access, id)
			result.AccessTokens++
		}
	}
	for id, token := range m.refresh {
		if token.ExpiresAt.Before(before) {
			delete(m.refresh, id)
			result.RefreshTokens++
		}
	}
	for id, device := range m.devices {
		if device.ExpiresAt.Before(before) {
			delete(m.byUserCode, device.UserCodeHash)
			delete(m.devices, id)
			result.DeviceCodes++
		}
	}
	return result, nil
}
