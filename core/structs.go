package core

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a user for authentication with enhanced fields
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Password     string    `json:"-"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	PasswordHash string    `json:"-"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

type MapUserProvider struct {
	users map[string]User
}

type DatabaseUserProvider struct {
	// Add your database connection or client here
}

// TokenData holds token information with refresh token support
type tokenData struct {
	accessToken      string
	refreshToken     string
	expiresAt        time.Time
	refreshExpiresAt time.Time
	userID           string
	isRevoked        bool
	tokenType        string // "access" or "refresh"
}

type InMemoryTokenStorage struct {
	tokens map[string]tokenData
	// Track refresh tokens separately for better management
	refreshTokens map[string]tokenData
	// Track user sessions for logout all functionality
	userSessions map[string][]string
}

// Claims represents JWT claims with enhanced user information
type Claims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"` // "access" or "refresh"
	SessionID string `json:"session_id"` // For tracking user sessions
	jwt.RegisteredClaims
}

// RefreshTokenClaims represents refresh token specific claims
type RefreshTokenClaims struct {
	UserID    string `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	SessionID string `json:"session_id"`
	TokenType string `json:"token_type"` // Always "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh token pair
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenType             string    `json:"token_type"` // "Bearer"
}

// UserSession represents an active user session
type UserSession struct {
	SessionID    string    `json:"session_id"`
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
}
