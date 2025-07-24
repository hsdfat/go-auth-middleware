# Enhanced JWT Authentication Middleware

## 🚀 New Features

### ✨ Refresh Token Support
- **Short-lived access tokens** (15 minutes default)
- **Long-lived refresh tokens** (7 days default)
- **Automatic token refresh** mechanism
- **Secure token rotation** on refresh

### 👤 Enhanced User Management
- **Email field** support
- **Role-based access control**
- **User activation status**
- **User session tracking**

### 🔐 Advanced Security
- **Session management** with cleanup
- **Multiple concurrent sessions** support
- **Device/session tracking** with IP and User-Agent
- **Logout from all devices** functionality
- **Token revocation** on logout

### 🎯 Role-Based Authorization
- **Role validation** middleware
- **Permission-based access** control
- **Multi-role authorization** support

## 📦 Installation

```bash
go get github.com/hsdfat/go-auth-middleware
```

## 🔧 Quick Start

### Basic Enhanced Usage

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/hsdfat/go-auth-middleware/ginauth"
    "github.com/hsdfat/go-auth-middleware/core"
)

func main() {
    r := gin.Default()

    // Create users with enhanced fields
    users := map[string]core.User{
        "admin": {
            ID:           1,
            Username:     "admin",
            Email:        "admin@example.com",
            Role:         "admin",
            PasswordHash: "$2a$10$...", // bcrypt hash
            IsActive:     true,
        },
    }

    userProvider := core.NewMapUserProvider(users)
    tokenStorage := core.NewInMemoryTokenStorage()

    // Enhanced auth middleware
    auth := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
        SecretKey:           "access-secret",
        RefreshSecretKey:    "refresh-secret",
        AccessTokenTimeout:  15 * time.Minute,
        RefreshTokenTimeout: 7 * 24 * time.Hour,
        UserProvider:        userProvider,
        TokenStorage:        tokenStorage,
        Authenticator:       ginauth.CreateEnhancedAuthenticator(userProvider),
        RoleAuthorizator:    ginauth.CreateRoleAuthorizator("admin", "user"),
    })

    // Routes
    r.POST("/auth/login", auth.LoginHandler)
    r.POST("/auth/refresh", auth.RefreshHandler)
    
    protected := r.Group("/api")
    protected.Use(auth.MiddlewareFunc())
    {
        protected.POST("/auth/logout", auth.LogoutHandler)
        protected.POST("/auth/logout-all", auth.LogoutAllHandler)
        protected.GET("/profile", profileHandler)
    }

    r.Run(":8080")
}
```

## 🔑 API Endpoints

### Authentication

#### Login
```http
POST /auth/login
Content-Type: application/json

{
    "username": "admin",
    "password": "admin123",
    "email": "admin@example.com",  # optional
    "remember": true               # optional - extends refresh token
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "access_token_expires_at": 1640995200,
        "refresh_token_expires_at": 1641600000,
        "token_type": "Bearer",
        "user": {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "role": "admin"
        }
    }
}
```

#### Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
    "refresh_token": "eyJ..."
}
```

**Response:**
```json
{
    "success": true,
    "data": {
        "access_token": "eyJ...",
        "refresh_token": "eyJ...",
        "access_token_expires_at": 1640995200,
        "refresh_token_expires_at": 1641600000,
        "token_type": "Bearer"
    }
}
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer eyJ...
```

**Response:**
```json
{
    "success": true,
    "message": "Successfully logged out"
}
```

#### Logout from All Devices
```http
POST /auth/logout-all
Authorization: Bearer eyJ...
```

**Response:**
```json
{
    "success": true,
    "message": "Successfully logged out from all devices"
}
```

#### Get User Sessions
```http
GET /auth/sessions
Authorization: Bearer eyJ...
```

**Response:**
```json
{
    "success": true,
    "data": {
        "current_session_id": "abc123",
        "sessions": [
            {
                "session_id": "abc123",
                "created_at": 1640995200,
                "last_activity": 1640999800,
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0...",
                "is_current": true
            }
        ]
    }
}
```

## 🛡️ Role-Based Authorization

### Simple Role Check
```go
// Only admin users
admin := api.Group("/admin")
admin.Use(requireRole("admin"))

// Multiple roles allowed
moderation := api.Group("/moderation")
moderation.Use(requireRoles("admin", "moderator"))
```

### Custom Authorization Middleware
```go
func requireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        userRole := c.MustGet("user_role").(string)
        if userRole != role {
            c.JSON(403, gin.H{"error": "Insufficient permissions"})
            c.Abort()
            return
        }
        c.Next()
    }
}
```

## 📊 Available Context Values

After authentication, these values are available in Gin context:

```go
func handler(c *gin.Context) {
    userID := c.MustGet("identity")        // User ID
    username := c.MustGet("username")      // Username
    email := c.MustGet("user_email")       // User email
    role := c.MustGet("user_role")         // User role
    sessionID := c.MustGet("SESSION_ID")   // Session ID
    
    // Use the values...
}
```

## ⚙️ Configuration Options

### Enhanced Auth Config
```go
type EnhancedAuthConfig struct {
    // JWT Configuration
    SecretKey           string        // Access token secret
    RefreshSecretKey    string        // Refresh token secret (should be different)
    AccessTokenTimeout  time.Duration // Access token expiry (e.g., 15m)
    RefreshTokenTimeout time.Duration // Refresh token expiry (e.g., 7d)
    
    // Security
    MaxConcurrentSessions int  // Max sessions per user (0 = unlimited)
    SingleSessionMode     bool // Only one session per user
    EnableTokenRevocation bool // Revoke tokens on logout
    CleanupInterval       time.Duration // Token cleanup interval
    
    // Storage & Providers
    TokenStorage  core.TokenStorage  // Token storage interface
    UserProvider  core.UserProvider  // User provider interface
    RoleProvider  core.RoleProvider  // Role provider interface (optional)
    
    // Authentication Functions
    Authenticator    func(*gin.Context) (*core.User, error)
    RoleAuthorizator func(string, *gin.Context) bool
    
    // Response Functions
    LoginResponse   func(*gin.Context, int, core.TokenPair, *core.User)
    RefreshResponse func(*gin.Context, int, core.TokenPair)
    LogoutResponse  func(*gin.Context, int, string)
    
    // Cookie Settings
    SendCookie        bool
    CookieName        string
    RefreshCookieName string
    CookieHTTPOnly    bool
    CookieSecure      bool
    CookieDomain      string
}
```

## 🔄 Backward Compatibility

The enhanced version maintains full backward compatibility with existing code:

```go
// Existing code continues to work
auth := ginauth.New(ginauth.AuthConfig{
    SecretKey:    "secret",
    TokenStorage: tokenStorage,
    UseBcrypt:    true,
    Authenticator: ginauth.BasicAuthenticator(userProvider),
    // ... other existing config
})
```

## 🏗️ Custom Implementations

### Custom User Provider
```go
type DatabaseUserProvider struct {
    db *sql.DB
}

func (p *DatabaseUserProvider) GetUserByUsername(username string) (*core.User, error) {
    var user core.User
    err := p.db.QueryRow(
        "SELECT id, username, email, role, password_hash, is_active FROM users WHERE username = ?",
        username,
    ).Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.PasswordHash, &user.IsActive)
    
    if err != nil {
        return nil, err
    }
    
    return &user, nil
}

func (p *DatabaseUserProvider) GetUserByEmail(email string) (*core.User, error) {
    // Implementation...
}

func (p *DatabaseUserProvider) UpdateUserLastLogin(userID interface{}, lastLogin time.Time) error {
    // Implementation...
}
```

### Custom Token Storage
```go
type RedisTokenStorage struct {
    client redis.Client
}

func (s *RedisTokenStorage) StoreTokenPair(sessionID, accessToken, refreshToken string, accessExpiry, refreshExpiry time.Time, userID interface{}) error {
    // Store access token
    s.client.Set(ctx, "access:"+sessionID, accessToken, time.Until(accessExpiry))
    
    // Store refresh token
    s.client.Set(ctx, "refresh:"+sessionID, refreshToken, time.Until(refreshExpiry))
    
    // Track user sessions
    s.client.SAdd(ctx, fmt.Sprintf("user_sessions:%v", userID), sessionID)
    
    return nil
}

func (s *RedisTokenStorage) GetAccessToken(sessionID string) (string, error) {
    return s.client.Get(ctx, "access:"+sessionID).Result()
}

// Implement other TokenStorage methods...
```

## 🧪 Testing Examples

### Login Test
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

### Access Protected Route
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

### Logout from All Devices
```bash
curl -X POST http://localhost:8080/auth/logout-all \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 🔒 Security Best Practices

### 1. Use Different Secrets
```go
auth := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
    SecretKey:        "your-access-token-secret-key-min-32-chars",
    RefreshSecretKey: "your-refresh-token-secret-key-different-from-access",
    // ...
})
```

### 2. Short Access Token Expiry
```go
AccessTokenTimeout:  15 * time.Minute,  // Short-lived
RefreshTokenTimeout: 7 * 24 * time.Hour, // Longer-lived
```

### 3. Secure Cookies in Production
```go
CookieSecure:   true,  // HTTPS only
CookieHTTPOnly: true,  // Prevent XSS
CookieSameSite: http.SameSiteStrictMode,
```

### 4. Enable Token Cleanup
```go
// Automatic cleanup of expired tokens
go func() {
    ticker := time.NewTicker(time.Hour)
    defer ticker.Stop()
    
    for range ticker.C {
        tokenStorage.CleanupExpiredTokens()
    }
}()
```

### 5. Limit Concurrent Sessions
```go
MaxConcurrentSessions: 5,    // Max 5 devices per user
SingleSessionMode:     false, // Allow multiple sessions
```

## 📱 Token Flow Diagram

```
┌─────────────┐    1. Login     ┌─────────────┐
│   Client    │ ───────────────► │   Server    │
│             │                 │             │
│             │ ◄─────────────── │             │
│             │  Access Token +  │             │
│             │  Refresh Token   │             │
└─────────────┘                 └─────────────┘
       │                               │
       │ 2. API Request                │
       │    (Access Token)             │
       │ ─────────────────────────────► │
       │                               │
       │ ◄───────────────────────────── │
       │      API Response             │
       │                               │
       │ 3. Access Token Expires       │
       │    Use Refresh Token          │
       │ ─────────────────────────────► │
       │                               │
       │ ◄───────────────────────────── │
       │   New Access Token +          │
       │   New Refresh Token           │
       │                               │
       │ 4. Logout (Optional)          │
       │ ─────────────────────────────► │
       │                               │
       │ ◄───────────────────────────── │
       │   Tokens Revoked              │
```

## 🚨 Error Handling

### Common Error Responses

#### 401 Unauthorized
```json
{
    "success": false,
    "error": true,
    "code": 401,
    "message": "Token is expired"
}
```

#### 403 Forbidden
```json
{
    "success": false,
    "error": true,
    "code": 403,
    "message": "Insufficient permissions"
}
```

#### 400 Bad Request
```json
{
    "success": false,
    "error": true,
    "code": 400,
    "message": "Invalid request data",
    "details": "Username is required"
}
```

## 📋 Migration Guide

### From Basic JWT to Enhanced JWT

#### Before (Basic)
```go
auth := ginauth.New(ginauth.AuthConfig{
    SecretKey: "secret",
    Timeout:   time.Hour,
    // ...
})
```

#### After (Enhanced)
```go
auth := ginauth.NewEnhanced(ginauth.EnhancedAuthConfig{
    SecretKey:           "access-secret",
    RefreshSecretKey:    "refresh-secret",
    AccessTokenTimeout:  15 * time.Minute,
    RefreshTokenTimeout: 7 * 24 * time.Hour,
    // ...
})
```

### Adding User Fields
```go
// Old user structure
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Password string `json:"-"`
}

// New enhanced user structure
type User struct {
    ID           int       `json:"id"`
    Username     string    `json:"username"`
    Password     string    `json:"-"`
    Email        string    `json:"email"`        // New
    Role         string    `json:"role"`         // New
    PasswordHash string    `json:"-"`            // New
    IsActive     bool      `json:"is_active"`    // New
    CreatedAt    time.Time `json:"created_at"`   // New
    UpdatedAt    time.Time `json:"updated_at"`   // New
}
```

## 🔧 Advanced Configuration

### Custom Session Management
```go
type CustomSessionManager struct {
    db *sql.DB
}

func (sm *CustomSessionManager) CreateSession(userID interface{}, ipAddress, userAgent string) (*core.UserSession, error) {
    sessionID, _ := core.GenerateSessionID()
    
    session := &core.UserSession{
        SessionID:    sessionID,
        UserID:       userID,
        CreatedAt:    time.Now(),
        LastActivity: time.Now(),
        IPAddress:    ipAddress,
        UserAgent:    userAgent,
    }
    
    // Store in database
    _, err := sm.db.Exec(
        "INSERT INTO user_sessions (session_id, user_id, created_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        session.SessionID, session.UserID, session.CreatedAt, session.LastActivity, session.IPAddress, session.UserAgent,
    )
    
    return session, err
}
```

### Role-Based Permissions
```go
type Permission struct {
    Name        string
    Description string
}

type Role struct {
    Name        string
    Permissions []Permission
}

type RoleProvider struct {
    roles map[string]Role
}

func (rp *RoleProvider) HasPermission(userID interface{}, permission string) (bool, error) {
    // Get user role
    user, err := userProvider.GetUserByID(userID)
    if err != nil {
        return false, err
    }
    
    // Check if role has permission
    if role, exists := rp.roles[user.Role]; exists {
        for _, perm := range role.Permissions {
            if perm.Name == permission {
                return true, nil
            }
        }
    }
    
    return false, nil
}
```

## 📊 Monitoring and Metrics

### Session Tracking
```go
func (auth *EnhancedGinAuthMiddleware) GetSessionMetrics() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get active sessions count
        totalSessions := 0
        userSessions := make(map[interface{}]int)
        
        // Collect metrics from token storage
        // Implementation depends on your storage
        
        c.JSON(200, gin.H{
            "total_active_sessions": totalSessions,
            "users_with_sessions":   len(userSessions),
            "avg_sessions_per_user": float64(totalSessions) / float64(len(userSessions)),
        })
    }
}
```

## 🎯 Performance Considerations

### 1. Token Storage Optimization
- Use Redis for production environments
- Implement connection pooling
- Set appropriate expiration times

### 2. Database Queries
- Index user lookup fields (username, email)
- Use prepared statements
- Implement query caching

### 3. Session Cleanup
```go
// Efficient cleanup with batch operations
func (s *RedisTokenStorage) CleanupExpiredTokens() error {
    // Use Redis SCAN for efficient iteration
    iter := s.client.Scan(ctx, 0, "access:*", 0).Iterator()
    
    for iter.Next(ctx) {
        key := iter.Val()
        ttl := s.client.TTL(ctx, key).Val()
        
        if ttl <= 0 {
            s.client.Del(ctx, key)
        }
    }
    
    return iter.Err()
}
```

## 📚 Additional Resources

- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Go Security Best Practices](https://golang.org/doc/security/)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.