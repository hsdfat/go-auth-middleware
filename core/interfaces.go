package core

import "time"

// TokenStorage interface for storing and managing tokens
type TokenStorage interface {
	StoreToken(tokenID string, token string, expiresAt time.Time) error
	GetToken(tokenID string) (string, error)
	DeleteToken(tokenID string) error
	IsTokenValid(tokenID string) (bool, error)
	RevokeAllUserTokens(userID interface{}) error
}

// UserProvider interface for getting user data from different sources
type UserProvider interface {
	GetUserByUsername(username string) (*User, error)
}
