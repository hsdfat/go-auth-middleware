package core

import (
	"fmt"
	"time"
)

// NewMapUserProvider creates a new MapUserProvider
func NewMapUserProvider(users map[string]User) *MapUserProvider {
	return &MapUserProvider{
		users: users,
	}
}

// GetUserByUsername implements UserProvider interface
func (p *MapUserProvider) GetUserByUsername(username string) (*User, error) {
	if user, exists := p.users[username]; exists {
		return &user, nil
	}
	return nil, fmt.Errorf("user not found")
}

// NewInMemoryTokenStorage creates a new InMemoryTokenStorage
func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return &InMemoryTokenStorage{
		tokens: make(map[string]tokenData),
	}
}

// StoreToken implements TokenStorage interface
func (s *InMemoryTokenStorage) StoreToken(tokenID string, token string, expiresAt time.Time) error {
	s.tokens[tokenID] = tokenData{
		token:     token,
		expiresAt: expiresAt,
	}
	return nil
}

// GetToken implements TokenStorage interface
func (s *InMemoryTokenStorage) GetToken(tokenID string) (string, error) {
	if data, exists := s.tokens[tokenID]; exists {
		return data.token, nil
	}
	return "", fmt.Errorf("token not found")
}

// DeleteToken implements TokenStorage interface
func (s *InMemoryTokenStorage) DeleteToken(tokenID string) error {
	delete(s.tokens, tokenID)
	return nil
}

// IsTokenValid implements TokenStorage interface
func (s *InMemoryTokenStorage) IsTokenValid(tokenID string) (bool, error) {
	if data, exists := s.tokens[tokenID]; exists {
		return time.Now().Before(data.expiresAt), nil
	}
	return false, nil
}

// RevokeAllUserTokens implements TokenStorage interface
func (s *InMemoryTokenStorage) RevokeAllUserTokens(userID interface{}) error {
	// This is a simple implementation. In a real application, you might want to
	// store user ID with tokens to implement this properly.
	return nil
}
