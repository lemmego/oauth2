package oauth2

// CreateRefreshToken satisfies RefreshWriter.
func (m *MemoryStore) CreateRefreshToken(_ Context, token *RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.refresh[token.ID]; exists {
		return ErrDuplicate
	}
	m.refresh[token.ID] = cloneRefresh(token)
	return nil
}
