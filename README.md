# Go Auth Middleware

A comprehensive, production-ready JWT authentication and authorization middleware for Go applications built with Gin framework. Features role-based access control (RBAC), token refresh mechanisms, session management, and user registration with role-based restrictions.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Authentication](#authentication)
  - [Login](#login)
  - [Registration](#registration)
  - [Token Refresh](#token-refresh)
  - [Logout](#logout)
- [Authorization](#authorization)
  - [Role-Based Access Control](#role-based-access-control)
  - [Custom Authorization](#custom-authorization)
- [Configuration](#configuration)
- [Interfaces](#interfaces)
- [Examples](#examples)
- [API Reference](#api-reference)

## Features

### Core Authentication
- **JWT-based Authentication**: Secure token-based authentication using HS256 algorithm
- **Token Pairs**: Access tokens (short-lived) and refresh tokens (long-lived) for improved security
- **Password Hashing**: Bcrypt password hashing for secure credential storage
- **Session Management**: Track and manage user sessions with IP and user agent information
- **Cookie Support**: Optional cookie-based token storage with configurable expiration

### User Management
- **User Registration**: Self-service registration with role-based restrictions
- **Role-Based Registration**: Control which roles can be assigned during registration
- **User Providers**: Flexible interface for custom user data sources
- **User Creator**: Extensible interface for user creation and validation
- **Email & Username Validation**: Uniqueness checking for user credentials

### Authorization & Access Control
- **Role-Based Authorization**: Restrict endpoints to specific user roles
- **Permission System**: Fine-grained permission-based access control
- **Custom Authorizers**: Implement custom authorization logic per endpoint
- **Multiple Session Support**: Track multiple concurrent sessions per user or enforce single session mode

### Token & Session Management
- **Automatic Token Refresh**: Securely refresh access tokens using refresh tokens
- **Session Tracking**: Monitor active sessions with timestamps and device information
- **Token Revocation**: Revoke tokens on logout with cleanup mechanisms
- **Concurrent Session Limits**: Control maximum concurrent sessions per user
- **Single Session Mode**: Enforce single session per user when needed
- **Automatic Cleanup**: Periodically cleanup expired tokens and sessions

### Security Features
- **Brute Force Protection**: Optional protection against login attempts
- **Session Activity Tracking**: Monitor and update session activity
- **User Active Status**: Validate user account status before operations
- **Configurable Timeouts**: Control access and refresh token expiration times
- **Secure Cookies**: HttpOnly, Secure, and SameSite cookie attributes

## Installation

```bash
go get github.com/hsdfat/go-auth-middleware
```

## Quick Start

### Basic Setup with Registration

```go
package main

import (
	"log"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/core"
	"github.com/hsdfat/go-auth-middleware/ginauth"
)

func main() {
	r := gin.Default()

	// Create initial users
	users := map[string]core.User{
		"admin": {
			ID:           "1",
			Username:     "admin",
			Email:        "admin@example.com",
			PasswordHash: ginauth.HashPassword("admin123"),
			Role:         "admin",
			IsActive:     true,
		},
	}

	// Create providers
	userProvider := core.NewMapUserProvider(users)
	userCreator := NewMapUserCreator(users) // Custom implementation
	tokenStorage := core.NewInMemoryTokenStorage()

	// Create auth middleware
	authMiddleware := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
		SecretKey:           "your-access-token-secret",
		RefreshSecretKey:    "your-refresh-token-secret",
		AccessTokenTimeout:  15 * time.Minute,
		RefreshTokenTimeout: 7 * 24 * time.Hour,
		
		TokenLookup:   "header:Authorization,cookie:jwt",
		TokenHeadName: "Bearer",
		Realm:         "go-auth",
		IdentityKey:   "identity",
		
		// Enable registration
		EnableRegistration: true,
		RegisterableRoles:  []string{"user"}, // Only 'user' role can self-register
		DefaultRole:        "user",
		
		// Providers
		TokenStorage: tokenStorage,
		UserProvider: userProvider,
		UserCreator:  userCreator,
		
		// Authentication
		Authenticator:    ginauth.CreateEnhancedAuthenticator(userProvider),
		RoleAuthorizator: ginauth.CreateRoleAuthorizator("admin", "user", "moderator"),
	})

	// Public endpoints
	r.POST("/auth/login", authMiddleware.LoginHandler)
	r.POST("/auth/register", authMiddleware.RegisterHandler)
	r.POST("/auth/refresh", authMiddleware.RefreshHandler)
	
	// Protected endpoints
	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(200, gin.H{"user_id": userID})
		})
		
		protected.POST("/logout", authMiddleware.LogoutHandler)
		protected.GET("/sessions", authMiddleware.GetUserSessionsHandler)
	}

	r.Run(":8080")
}
```

## Authentication

### Login

**Endpoint**: `POST /auth/login`

**Request**:
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response**:
```json
{
  "success": true,
  "code": 200,
  "data": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "access_token_expires_at": 1701363442,
    "refresh_token_expires_at": 1702000000,
    "token_type": "Bearer",
    "user": {
      "id": "1",
      "username": "admin",
      "email": "admin@example.com",
      "role": "admin"
    }
  }
}
```

### Registration

**Endpoint**: `POST /auth/register`

**Request**:
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "securepass123"
}
```

**Optional**: Request with specific role (if allowed):
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "securepass123",
  "role": "user"
}
```

**Response**:
```json
{
  "success": true,
  "code": 201,
  "message": "User registered successfully",
  "data": {
    "user_id": "123456",
    "username": "newuser",
    "email": "newuser@example.com",
    "role": "user",
    "created_at": 1701360000
  }
}
```

**Features**:
- Username and email validation for uniqueness
- Automatic password hashing with bcrypt
- Role-based registration restrictions
- Configurable default role for new users
- Validation of minimum password length (default: 8 characters)

### Token Refresh

**Endpoint**: `POST /auth/refresh`

**Request** (Body):
```json
{
  "refresh_token": "eyJhbGc..."
}
```

**Alternative** (Cookie or Header):
- Cookie: `refresh_token` cookie automatically extracted
- Header: `X-Refresh-Token` header supported

**Response**:
```json
{
  "success": true,
  "code": 200,
  "data": {
    "access_token": "eyJhbGc...",
    "refresh_token": "eyJhbGc...",
    "access_token_expires_at": 1701363442,
    "refresh_token_expires_at": 1702000000,
    "token_type": "Bearer"
  }
}
```

### Logout

**Endpoint**: `POST /auth/logout`

**Authentication**: Required (Bearer token)

**Response**:
```json
{
  "success": true,
  "code": 200,
  "message": "Successfully logged out"
}
```

**Logout All Sessions**:

**Endpoint**: `POST /auth/logout-all`

**Response**:
```json
{
  "success": true,
  "code": 200,
  "message": "Successfully logged out from all devices"
}
```

## Authorization

### Role-Based Access Control

Restrict endpoints to specific roles:

```go
// Create role authorizer
roleAuthorizator := ginauth.CreateRoleAuthorizator("admin", "moderator")

authMiddleware := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
    // ... other config ...
    RoleAuthorizator: roleAuthorizator,
})

// Admin-only routes
adminGroup := r.Group("/api/admin")
adminGroup.Use(authMiddleware.MiddlewareFunc())
adminGroup.Use(requireRole("admin"))
{
    adminGroup.GET("/users", listUsers)
    adminGroup.POST("/users", createUser)
}
```

### Custom Authorization

```go
// Custom authorizer function
customAuthorizator := func(data interface{}, c *gin.Context) bool {
    claims := data.(*core.Claims)
    // Custom logic: allow only if user created more than 1 day ago
    return time.Since(claims.IssuedAt.Time) > 24*time.Hour
}

authMiddleware := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
    // ... other config ...
    Authorizator: customAuthorizator,
})
```

### Per-Endpoint Authorization

```go
protected := r.Group("/api")
protected.Use(authMiddleware.MiddlewareFunc())
{
    // Require admin role for this specific endpoint
    protected.DELETE("/dangerous", requireRole("admin"), dangerousHandler)
}

func requireRole(requiredRole string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRole := c.MustGet("user_role").(string)
        if userRole != requiredRole {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "insufficient permissions",
            })
            c.Abort()
            return
        }
        c.Next()
    }
}
```

## Configuration

### EnhancedAuthConfig

```go
type EnhancedAuthConfig struct {
	// JWT Configuration
	SecretKey           string        // Secret for access tokens
	RefreshSecretKey    string        // Secret for refresh tokens
	AccessTokenTimeout  time.Duration // Access token expiry (default: 15m)
	RefreshTokenTimeout time.Duration // Refresh token expiry (default: 7d)
	
	// Token Lookup Configuration
	TokenLookup   string // "header:Authorization,query:token,cookie:jwt"
	TokenHeadName string // "Bearer"
	
	// General Configuration
	Realm       string              // Realm name for WWW-Authenticate
	IdentityKey string              // Key for storing user ID in context
	TimeFunc    func() time.Time    // Time function (for testing)
	
	// Cookie Configuration
	SendCookie        bool           // Enable cookie storage
	CookieName        string         // Access token cookie name
	RefreshCookieName string         // Refresh token cookie name
	CookieMaxAge      int            // Cookie max age in seconds
	CookieDomain      string         // Cookie domain
	CookieSecure      bool           // HTTPS only
	CookieHTTPOnly    bool           // JavaScript access disabled
	CookieSameSite    http.SameSite  // SameSite attribute
	
	// Storage and Providers
	TokenStorage   core.TokenStorage   // Token storage implementation
	UserProvider   core.UserProvider   // User data provider
	UserCreator    core.UserCreator    // User creation provider
	RoleProvider   core.RoleProvider   // Role management (optional)
	SessionManager core.SessionManager // Session management (optional)
	
	// Registration Configuration
	EnableRegistration bool     // Enable registration endpoint
	RegisterableRoles  []string // Roles assignable during registration
	DefaultRole        string   // Default role for new users
	
	// Authentication and Authorization Functions
	Authenticator     func(c *gin.Context) (*core.User, error)
	Authorizator      func(data interface{}, c *gin.Context) bool
	RoleAuthorizator  func(role string, c *gin.Context) bool
	IdentityHandler   func(c *gin.Context) interface{}
	
	// Response Functions
	Unauthorized    func(c *gin.Context, code int, message string)
	LoginResponse   func(c *gin.Context, code int, tokenPair core.TokenPair, user *core.User)
	LogoutResponse  func(c *gin.Context, code int, message string)
	RefreshResponse func(c *gin.Context, code int, tokenPair core.TokenPair)
	RegisterResponse func(c *gin.Context, code int, user *core.User)
	
	// Security Configuration
	EnableBruteForceProtection bool          // Brute force protection
	MaxLoginAttempts          int           // Max attempts before lockout
	LockoutDuration           time.Duration // Lockout duration
	RequireEmailVerification  bool          // Email verification required
	EnableTwoFactor           bool          // Two-factor authentication
	
	// Session Configuration
	MaxConcurrentSessions int  // Max concurrent sessions per user
	SingleSessionMode     bool // Only one session per user
	
	// Token Configuration
	EnableTokenRevocation bool          // Revoke tokens on logout
	CleanupInterval       time.Duration // Token cleanup interval
}
```

## Interfaces

### UserProvider

Retrieve user information:

```go
type UserProvider interface {
	GetUserByUsername(username string) (*User, error)
	GetUserByID(userID string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUserLastLogin(userID string, lastLogin time.Time) error
	IsUserActive(userID string) (bool, error)
}
```

### UserCreator

Create and validate users:

```go
type UserCreator interface {
	CreateUser(user *User) error
	UserExists(username string, email string) (bool, error)
	IsUsernameAvailable(username string) (bool, error)
	IsEmailAvailable(email string) (bool, error)
}
```

### TokenStorage

Manage tokens and sessions:

```go
type TokenStorage interface {
	// Access token methods
	StoreTokenPair(sessionID string, accessToken, refreshToken string, 
		accessExpiresAt, refreshExpiresAt time.Time, userID string) error
	GetAccessToken(sessionID string) (string, error)
	GetRefreshToken(sessionID string) (string, error)
	
	// Token validation
	IsAccessTokenValid(sessionID string) (bool, error)
	IsRefreshTokenValid(sessionID string) (bool, error)
	
	// Token management
	DeleteTokenPair(sessionID string) error
	RefreshTokenPair(sessionID string, newAccessToken, newRefreshToken string,
		accessExpiresAt, refreshExpiresAt time.Time) error
	
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
```

### RoleProvider (Optional)

Fine-grained role and permission management:

```go
type RoleProvider interface {
	GetUserRoles(userID string) ([]string, error)
	HasRole(userID string, role string) (bool, error)
	HasPermission(userID string, permission string) (bool, error)
	GetRolePermissions(role string) ([]string, error)
}
```

## Examples

### Complete Example with Registration

See [`examples/jwt/main.go`](examples/jwt/main.go) for a complete working example with:
- User login with JWT tokens
- User registration with role-based restrictions
- Token refresh mechanism
- Session management
- Role-based access control
- Multiple concurrent sessions

**Run the example**:
```bash
cd examples/jwt
go run main.go
```

**Test Registration**:
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "securepass123"
  }'
```

**Test Login**:
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Access Protected Route**:
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## API Reference

### Handlers

#### LoginHandler
- **Method**: POST
- **Endpoint**: `/auth/login`
- **Authentication**: None (public)
- **Purpose**: Authenticate user and return access/refresh tokens
- **Customization**: Via `Authenticator` config function

#### RegisterHandler
- **Method**: POST
- **Endpoint**: `/auth/register`
- **Authentication**: None (public)
- **Purpose**: Register new user with optional role assignment
- **Customization**: Via `EnableRegistration`, `RegisterableRoles`, `UserCreator`

#### RefreshHandler
- **Method**: POST
- **Endpoint**: `/auth/refresh`
- **Authentication**: None (public, but requires valid refresh token)
- **Purpose**: Get new access token using refresh token
- **Customization**: Via `RefreshResponse` config function

#### LogoutHandler
- **Method**: POST
- **Endpoint**: `/auth/logout`
- **Authentication**: Required
- **Purpose**: Logout current session
- **Customization**: Via `LogoutResponse` config function

#### LogoutAllHandler
- **Method**: POST
- **Endpoint**: `/auth/logout-all`
- **Authentication**: Required
- **Purpose**: Logout from all devices/sessions

#### GetUserSessionsHandler
- **Method**: GET
- **Endpoint**: `/auth/sessions`
- **Authentication**: Required
- **Purpose**: List active sessions for current user

### Context Variables

After middleware validation, the following variables are available in the request context:

- `identity`: User ID (configured via `IdentityKey`)
- `user_email`: User email
- `user_role`: User role
- `username`: Username
- `SESSION_ID`: Current session ID
- `JWT_PAYLOAD`: Full JWT claims

### Status Codes

- `200 OK`: Successful authentication/refresh/logout
- `201 Created`: Successful registration
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Missing or invalid credentials/tokens
- `403 Forbidden`: Insufficient permissions or role restrictions
- `409 Conflict`: Username/email already exists during registration
- `500 Internal Server Error`: Server error

## Security Considerations

1. **Secret Keys**: Use strong, randomly generated secret keys for both access and refresh tokens
2. **HTTPS**: Always use HTTPS in production
3. **Token Timeouts**: Keep access token timeout short (15-30 minutes) and refresh token timeout reasonable (7 days)
4. **Cookie Security**: Enable `CookieSecure` and `CookieHTTPOnly` in production
5. **CORS**: Configure CORS appropriately for your frontend
6. **Rate Limiting**: Implement rate limiting on authentication endpoints
7. **Token Storage**: In production, use a proper database instead of in-memory storage

## License

MIT
