package ginauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/core"
)

var (
	CheckPasswordHash = core.CheckPasswordHash
	HashPassword	  = core.HashPassword
)
// EnhancedAuthConfig holds enhanced configuration for the authentication middleware
type EnhancedAuthConfig struct {
	// JWT Configuration
	SecretKey           string // Secret key for access tokens
	RefreshSecretKey    string // Secret key for refresh tokens (should be different)
	AccessTokenTimeout  time.Duration // Access token expiry (e.g., 15 minutes)
	RefreshTokenTimeout time.Duration // Refresh token expiry (e.g., 7 days)
	
	// Token Lookup Configuration
	TokenLookup   string // Token lookup method: "header:Authorization,query:token,cookie:jwt"
	TokenHeadName string // Token header name: "Bearer"
	
	// General Configuration
	Realm       string // Realm name
	IdentityKey string // Identity key for context
	TimeFunc    func() time.Time // Time function for testing
	
	// Cookie Configuration
	SendCookie        bool   // Whether to send cookies
	CookieName        string // Access token cookie name
	RefreshCookieName string // Refresh token cookie name
	CookieMaxAge      int    // Cookie max age in seconds
	CookieDomain      string // Cookie domain
	CookieSecure      bool   // Cookie secure flag
	CookieHTTPOnly    bool   // Cookie HTTP only flag
	CookieSameSite    http.SameSite // Cookie SameSite attribute
	
	// Storage and Providers
	TokenStorage   core.TokenStorage   // Token storage interface
	UserProvider   core.UserProvider   // User provider interface
	RoleProvider   core.RoleProvider   // Role provider interface (optional)
	SessionManager core.SessionManager // Session manager interface (optional)
	
	// Authentication and Authorization Functions
	Authenticator     func(c *gin.Context) (*core.User, error)
	Authorizator      func(data interface{}, c *gin.Context) bool
	RoleAuthorizator  func(role string, c *gin.Context) bool // Role-based authorization
	IdentityHandler   func(c *gin.Context) interface{}
	
	// Response Functions
	Unauthorized    func(c *gin.Context, code int, message string)
	LoginResponse   func(c *gin.Context, code int, tokenPair core.TokenPair, user *core.User)
	LogoutResponse  func(c *gin.Context, code int, message string)
	RefreshResponse func(c *gin.Context, code int, tokenPair core.TokenPair)
	
	// Security Configuration
	EnableBruteForceProtection bool          // Enable brute force protection
	MaxLoginAttempts          int           // Max login attempts before lockout
	LockoutDuration           time.Duration // Lockout duration
	RequireEmailVerification  bool          // Require email verification
	EnableTwoFactor           bool          // Enable two-factor authentication
	
	// Session Configuration
	MaxConcurrentSessions int  // Maximum concurrent sessions per user (0 = unlimited)
	SingleSessionMode     bool // Only allow one session per user
	
	// Token Configuration
	EnableTokenRevocation bool // Enable token revocation on logout
	CleanupInterval       time.Duration // Interval for cleaning up expired tokens
}

// LoginRequest represents the login request structure
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Email    string `json:"email,omitempty"`
	Remember bool   `json:"remember,omitempty"` // For extended refresh token expiry
}

// RefreshRequest represents the refresh token request structure
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest represents the logout request structure
type LogoutRequest struct {
	LogoutAll bool `json:"logout_all,omitempty"` // Logout from all devices
}

// Enhanced response structures

// LoginResponse represents the response returned after a successful login
type EnhancedLoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    struct {
		AccessToken           string `json:"access_token"`
		RefreshToken          string `json:"refresh_token"`
		AccessTokenExpiresAt  int64  `json:"access_token_expires_at"`
		RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at"`
		TokenType             string `json:"token_type"`
		User                  struct {
			ID       interface{} `json:"id"`
			Username string      `json:"username"`
			Email    string      `json:"email"`
			Role     string      `json:"role"`
		} `json:"user"`
		SessionInfo struct {
			SessionID    string `json:"session_id"`
			CreatedAt    int64  `json:"created_at"`
			ExpiresAt    int64  `json:"expires_at"`
			IPAddress    string `json:"ip_address,omitempty"`
			UserAgent    string `json:"user_agent,omitempty"`
		} `json:"session_info,omitempty"`
	} `json:"data"`
}

// RefreshResponse represents the response returned after refreshing a token
type EnhancedRefreshResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    struct {
		AccessToken           string `json:"access_token"`
		RefreshToken          string `json:"refresh_token"`
		AccessTokenExpiresAt  int64  `json:"access_token_expires_at"`
		RefreshTokenExpiresAt int64  `json:"refresh_token_expires_at"`
		TokenType             string `json:"token_type"`
	} `json:"data"`
}

// LogoutResponse represents the response returned after a successful logout
type EnhancedLogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		LoggedOutSessions int `json:"logged_out_sessions,omitempty"`
	} `json:"data,omitempty"`
}

// SessionsResponse represents the response for user sessions
type SessionsResponse struct {
	Success bool `json:"success"`
	Data    struct {
		CurrentSessionID string `json:"current_session_id"`
		Sessions         []struct {
			SessionID    string `json:"session_id"`
			CreatedAt    int64  `json:"created_at"`
			LastActivity int64  `json:"last_activity"`
			IPAddress    string `json:"ip_address"`
			UserAgent    string `json:"user_agent"`
			IsCurrent    bool   `json:"is_current"`
		} `json:"sessions"`
	} `json:"data"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   bool   `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Helper functions for creating enhanced authenticators

// CreateEnhancedAuthenticator creates an enhanced authenticator with additional validation
func CreateEnhancedAuthenticator(userProvider core.UserProvider) func(*gin.Context) (*core.User, error) {
	return func(c *gin.Context) (*core.User, error) {
		var loginRequest LoginRequest
		if err := c.ShouldBindJSON(&loginRequest); err != nil {
			return nil, err
		}

		// Try to get user by username or email
		var user *core.User
		var err error
		
		if loginRequest.Email != "" {
			user, err = userProvider.GetUserByEmail(loginRequest.Email)
		} else {
			user, err = userProvider.GetUserByUsername(loginRequest.Username)
		}
		
		if err != nil {
			return nil, errors.New("invalid credentials")
		}

		// Validate password
		var passwordValid bool
		if user.PasswordHash != "" {
			passwordValid = CheckPasswordHash(loginRequest.Password, user.PasswordHash)
		} else if user.Password != "" {
			passwordValid = user.Password == loginRequest.Password
		}

		if !passwordValid {
			return nil, errors.New("invalid credentials")
		}

		// Check if user is active
		if !user.IsActive {
			return nil, errors.New("account is inactive")
		}

		return user, nil
	}
}

// CreateRoleAuthorizator creates a role-based authorization function
func CreateRoleAuthorizator(allowedRoles ...string) func(string, *gin.Context) bool {
	roleMap := make(map[string]bool)
	for _, role := range allowedRoles {
		roleMap[role] = true
	}
	
	return func(userRole string, c *gin.Context) bool {
		if len(roleMap) == 0 {
			return true // No role restrictions
		}
		return roleMap[userRole]
	}
}

// CreatePermissionAuthorizator creates a permission-based authorization function
func CreatePermissionAuthorizator(roleProvider core.RoleProvider, requiredPermission string) func(string, *gin.Context) bool {
	return func(userRole string, c *gin.Context) bool {
		if roleProvider == nil {
			return true
		}
		
		userID := c.MustGet("identity").(string)
		hasPermission, err := roleProvider.HasPermission(userID, requiredPermission)
		if err != nil {
			return false
		}
		
		return hasPermission
	}
}