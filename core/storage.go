package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
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

// GetUserByID implements UserProvider interface
func (p *MapUserProvider) GetUserByID(userID string) (*User, error) {
	for _, user := range p.users {
		if user.ID == userID {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// GetUserByEmail implements UserProvider interface
func (p *MapUserProvider) GetUserByEmail(email string) (*User, error) {
	for _, user := range p.users {
		if user.Email == email {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

// UpdateUserLastLogin implements UserProvider interface
func (p *MapUserProvider) UpdateUserLastLogin(userID string, lastLogin time.Time) error {
	for username, user := range p.users {
		if user.ID == userID {
			user.UpdatedAt = lastLogin
			p.users[username] = user
			return nil
		}
	}
	return fmt.Errorf("user not found")
}

// IsUserActive implements UserProvider interface
func (p *MapUserProvider) IsUserActive(userID string) (bool, error) {
	fmt.Println("Checking if user is active:", userID)
	for _, user := range p.users {
		fmt.Println("User ID:", user.ID, user.IsActive)
		if user.ID == userID {
			return user.IsActive, nil
		}
	}
	return false, fmt.Errorf("user not found")
}

// Enhanced InMemoryTokenStorage with refresh token support
type EnhancedInMemoryTokenStorage struct {
	tokens        map[string]tokenData
	refreshTokens map[string]tokenData
	userSessions  map[string][]string
	sessions      map[string]UserSession
	mutex         sync.RWMutex
}

// NewEnhancedInMemoryTokenStorage creates a new enhanced token storage
func NewEnhancedInMemoryTokenStorage() *EnhancedInMemoryTokenStorage {
	return &EnhancedInMemoryTokenStorage{
		tokens:        make(map[string]tokenData),
		refreshTokens: make(map[string]tokenData),
		userSessions:  make(map[string][]string),
		sessions:      make(map[string]UserSession),
	}
}

// StoreTokenPair implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) StoreTokenPair(sessionID string, accessToken, refreshToken string, accessExpiresAt, refreshExpiresAt time.Time, userID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Store access token
	s.tokens[sessionID] = tokenData{
		accessToken:      accessToken,
		refreshToken:     refreshToken,
		expiresAt:        accessExpiresAt,
		refreshExpiresAt: refreshExpiresAt,
		userID:           userID,
		isRevoked:        false,
		tokenType:        "access",
	}

	// Store refresh token separately
	s.refreshTokens[sessionID] = tokenData{
		accessToken:      accessToken,
		refreshToken:     refreshToken,
		expiresAt:        accessExpiresAt,
		refreshExpiresAt: refreshExpiresAt,
		userID:           userID,
		isRevoked:        false,
		tokenType:        "refresh",
	}

	// Track user sessions
	if sessions, exists := s.userSessions[userID]; exists {
		s.userSessions[userID] = append(sessions, sessionID)
	} else {
		s.userSessions[userID] = []string{sessionID}
	}

	return nil
}

// GetAccessToken implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) GetAccessToken(sessionID string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if data, exists := s.tokens[sessionID]; exists && !data.isRevoked {
		return data.accessToken, nil
	}
	return "", fmt.Errorf("access token not found")
}

// GetRefreshToken implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) GetRefreshToken(sessionID string) (string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if data, exists := s.refreshTokens[sessionID]; exists && !data.isRevoked {
		return data.refreshToken, nil
	}
	return "", fmt.Errorf("refresh token not found")
}

// IsAccessTokenValid implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) IsAccessTokenValid(sessionID string) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if data, exists := s.tokens[sessionID]; exists {
		return !data.isRevoked && time.Now().Before(data.expiresAt), nil
	}
	return false, nil
}

// IsRefreshTokenValid implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) IsRefreshTokenValid(sessionID string) (bool, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if data, exists := s.refreshTokens[sessionID]; exists {
		return !data.isRevoked && time.Now().Before(data.refreshExpiresAt), nil
	}
	return false, nil
}

// DeleteTokenPair implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) DeleteTokenPair(sessionID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Get user ID before deletion for session cleanup
	var userID string
	if data, exists := s.tokens[sessionID]; exists {
		userID = data.userID
	}

	// Delete tokens
	delete(s.tokens, sessionID)
	delete(s.refreshTokens, sessionID)

	// Remove from user sessions
	if userID != "" {
		if sessions, exists := s.userSessions[userID]; exists {
			var updatedSessions []string
			for _, sid := range sessions {
				if sid != sessionID {
					updatedSessions = append(updatedSessions, sid)
				}
			}
			if len(updatedSessions) == 0 {
				delete(s.userSessions, userID)
			} else {
				s.userSessions[userID] = updatedSessions
			}
		}
	}

	// Delete session
	delete(s.sessions, sessionID)

	return nil
}

// RefreshTokenPair implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) RefreshTokenPair(sessionID string, newAccessToken, newRefreshToken string, accessExpiresAt, refreshExpiresAt time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if session exists
	if data, exists := s.tokens[sessionID]; exists {
		// Update access token
		data.accessToken = newAccessToken
		data.expiresAt = accessExpiresAt
		s.tokens[sessionID] = data

		// Update refresh token
		if refreshData, exists := s.refreshTokens[sessionID]; exists {
			refreshData.refreshToken = newRefreshToken
			refreshData.refreshExpiresAt = refreshExpiresAt
			refreshData.accessToken = newAccessToken
			refreshData.expiresAt = accessExpiresAt
			s.refreshTokens[sessionID] = refreshData
		}

		return nil
	}
	return fmt.Errorf("session not found")
}

// RevokeAllUserTokens implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) RevokeAllUserTokens(userID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if sessions, exists := s.userSessions[userID]; exists {
		for _, sessionID := range sessions {
			// Mark tokens as revoked
			if data, exists := s.tokens[sessionID]; exists {
				data.isRevoked = true
				s.tokens[sessionID] = data
			}
			if data, exists := s.refreshTokens[sessionID]; exists {
				data.isRevoked = true
				s.refreshTokens[sessionID] = data
			}
			// Delete session
			delete(s.sessions, sessionID)
		}
		// Clear user sessions
		delete(s.userSessions, userID)
	}
	return nil
}

// GetUserActiveSessions implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) GetUserActiveSessions(userID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if sessions, exists := s.userSessions[userID]; exists {
		var activeSessions []string
		for _, sessionID := range sessions {
			if data, exists := s.tokens[sessionID]; exists && !data.isRevoked && time.Now().Before(data.expiresAt) {
				activeSessions = append(activeSessions, sessionID)
			}
		}
		return activeSessions, nil
	}
	return []string{}, nil
}

// StoreUserSession implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) StoreUserSession(session UserSession) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.sessions[session.SessionID] = session
	return nil
}

// GetUserSession implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) GetUserSession(sessionID string) (*UserSession, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	if session, exists := s.sessions[sessionID]; exists {
		return &session, nil
	}
	return nil, fmt.Errorf("session not found")
}

// UpdateSessionActivity implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) UpdateSessionActivity(sessionID string, lastActivity time.Time) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if session, exists := s.sessions[sessionID]; exists {
		session.LastActivity = lastActivity
		s.sessions[sessionID] = session
		return nil
	}
	return fmt.Errorf("session not found")
}

// DeleteUserSession implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) DeleteUserSession(sessionID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

// CleanupExpiredTokens implements TokenStorage interface
func (s *EnhancedInMemoryTokenStorage) CleanupExpiredTokens() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()

	// Clean up expired access tokens
	for sessionID, data := range s.tokens {
		if now.After(data.expiresAt) {
			delete(s.tokens, sessionID)
		}
	}

	// Clean up expired refresh tokens
	for sessionID, data := range s.refreshTokens {
		if now.After(data.refreshExpiresAt) {
			delete(s.refreshTokens, sessionID)
		}
	}

	// Clean up expired sessions
	for sessionID := range s.sessions {
		if _, exists := s.tokens[sessionID]; !exists {
			delete(s.sessions, sessionID)
		}
	}

	// Update user sessions to remove expired ones
	for userID, sessions := range s.userSessions {
		var activeSessions []string
		for _, sessionID := range sessions {
			if _, exists := s.tokens[sessionID]; exists {
				activeSessions = append(activeSessions, sessionID)
			}
		}
		if len(activeSessions) == 0 {
			delete(s.userSessions, userID)
		} else {
			s.userSessions[userID] = activeSessions
		}
	}

	return nil
}

// GenerateSessionID creates a unique session identifier
func GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Backward compatibility - create alias for original storage
func NewInMemoryTokenStorage() TokenStorage {
	return NewEnhancedInMemoryTokenStorage()
}
