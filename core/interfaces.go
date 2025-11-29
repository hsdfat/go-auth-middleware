package core

import "time"

// Enhanced TokenStorage interface for refresh token support
type TokenStorage interface {
	// Access token methods
	StoreTokenPair(sessionID string, accessToken, refreshToken string, accessExpiresAt, refreshExpiresAt time.Time, userID string) error
	GetAccessToken(sessionID string) (string, error)
	GetRefreshToken(sessionID string) (string, error)

	// Token validation
	IsAccessTokenValid(sessionID string) (bool, error)
	IsRefreshTokenValid(sessionID string) (bool, error)

	// Token management
	DeleteTokenPair(sessionID string) error
	RefreshTokenPair(sessionID string, newAccessToken, newRefreshToken string, accessExpiresAt, refreshExpiresAt time.Time) error

	// User session management
	RevokeAllUserTokens(userID string) error
	GetUserActiveSessions(userID string) ([]string, error)

	// Session tracking
	StoreUserSession(session UserSession) error
	GetUserSession(sessionID string) (*UserSession, error)
	UpdateSessionActivity(sessionID string, lastActivity time.Time) error
	DeleteUserSession(sessionID string) error

	// Cleanup expired tokens
	CleanupExpiredTokens() error
}

// Enhanced UserProvider interface
type UserProvider interface {
	GetUserByUsername(username string) (*User, error)
	GetUserByID(userID string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUserLastLogin(userID string, lastLogin time.Time) error
	IsUserActive(userID string) (bool, error)
}

// UserCreator interface for creating new users
type UserCreator interface {
	CreateUser(user *User) error
	UserExists(username string, email string) (bool, error)
	IsUsernameAvailable(username string) (bool, error)
	IsEmailAvailable(email string) (bool, error)
}

// Role-based access control interface
type RoleProvider interface {
	GetUserRoles(userID string) ([]string, error)
	HasRole(userID string, role string) (bool, error)
	HasPermission(userID string, permission string) (bool, error)
	GetRolePermissions(role string) ([]string, error)
}

// Session management interface
type SessionManager interface {
	CreateSession(userID string, ipAddress, userAgent string) (*UserSession, error)
	GetSession(sessionID string) (*UserSession, error)
	UpdateSession(sessionID string, lastActivity time.Time) error
	RevokeSession(sessionID string) error
	RevokeAllUserSessions(userID string) error
	GetUserActiveSessions(userID string) ([]*UserSession, error)
	CleanupExpiredSessions() error
}
