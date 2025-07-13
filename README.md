# Go Auth Middleware

A flexible JWT authentication middleware for Gin framework with bcrypt password hashing and token storage support.

## Features

- JWT-based authentication
- Bcrypt password hashing
- Token storage interface (with in-memory implementation)
- Token refresh functionality
- Cookie support
- Flexible configuration
- Middleware for Gin framework

## Installation

```bash
go get github.com/hsdfat/go-auth-middleware
```

## Quick Start

### Using UserProvider Interface (Recommended)

```go
package main

import (
    "github.com/gin-gonic/gin"
    "github.com/hsdfat/go-auth-middleware/ginauth"
)

func main() {
    r := gin.Default()

    // Create users with bcrypt password hashing
    users, err := ginauth.CreateUserMapWithBcrypt([]struct {
        ID       int
        Username string
        Password string
    }{
        {ID: 1, Username: "admin", Password: "admin123"},
        {ID: 2, Username: "user", Password: "user123"},
    })
    if err != nil {
        log.Fatal("Failed to create users:", err)
    }

    // Create user provider
    userProvider := ginauth.NewMapUserProvider(users)

    // Create token storage
    tokenStorage := ginauth.NewInMemoryTokenStorage()

    // Create auth middleware
    authMiddleware := ginauth.New(ginauth.AuthConfig{
        SecretKey:    "your-secret-key",
        TokenStorage: tokenStorage,
        UseBcrypt:    true,
        Authenticator: ginauth.BasicAuthenticator(userProvider),
        PayloadFunc:  ginauth.BasicPayloadFunc(),
        IdentityHandler: ginauth.BasicIdentityHandler(),
    })

    // Routes
    r.POST("/login", authMiddleware.LoginHandler)
    r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
    r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

    // Protected routes
    protected := r.Group("/api")
    protected.Use(authMiddleware.MiddlewareFunc())
    {
        protected.GET("/profile", func(c *gin.Context) {
            userID := c.MustGet("identity")
            c.JSON(200, gin.H{"user_id": userID})
        })
    }

    r.Run(":8080")
}
```

### Using Legacy Map-based Approach (Backward Compatibility)

```go
// For backward compatibility, you can still use the map directly
authMiddleware := ginauth.New(ginauth.AuthConfig{
    SecretKey:    "your-secret-key",
    TokenStorage: tokenStorage,
    UseBcrypt:    true,
    Authenticator: ginauth.LegacyBasicAuthenticator(users), // Legacy approach
    PayloadFunc:  ginauth.BasicPayloadFunc(),
    IdentityHandler: ginauth.BasicIdentityHandler(),
})
```

## Configuration

### AuthConfig

```go
type AuthConfig struct {
    SecretKey       string                    // JWT signing secret
    TokenLookup     string                    // Token lookup method: "header:Authorization,query:token,cookie:jwt"
    TokenHeadName   string                    // Token header name: "Bearer"
    Realm           string                    // Realm name
    IdentityKey     string                    // Identity key for context
    IdentityHandler func(c *gin.Context) interface{}
    Authenticator   func(c *gin.Context) (interface{}, error)
    Authorizator    func(data interface{}, c *gin.Context) bool
    PayloadFunc     func(data interface{}) jwt.MapClaims
    Unauthorized    func(c *gin.Context, code int, message string)
    LoginResponse   func(c *gin.Context, code int, token string, expire time.Time)
    LogoutResponse  func(c *gin.Context, code int)
    RefreshResponse func(c *gin.Context, code int, token string, expire time.Time)
    TimeFunc        func() time.Time
    Timeout         time.Duration
    MaxRefresh      time.Duration
    SendCookie      bool
    CookieName      string
    CookieMaxAge    int
    CookieDomain    string
    CookieHTTPOnly  bool
    CookieSameSite  http.SameSite
    TokenStorage    TokenStorage              // Token storage interface
    UseBcrypt       bool                      // Enable bcrypt password hashing
}
```

## User Authentication

### UserProvider Interface

The `UserProvider` interface allows you to use any data source for user authentication:

```go
type UserProvider interface {
    GetUserByUsername(username string) (*User, error)
}
```

### Map-based User Provider

```go
// Create users with bcrypt password hashing
users, err := ginauth.CreateUserMapWithBcrypt([]struct {
    ID       int
    Username string
    Password string
}{
    {ID: 1, Username: "admin", Password: "admin123"},
    {ID: 2, Username: "user", Password: "user123"},
})

// Create user provider
userProvider := ginauth.NewMapUserProvider(users)

// Use with authenticator
authenticator := ginauth.BasicAuthenticator(userProvider)
```

### Database User Provider

You can implement your own database user provider:

```go
type CustomDatabaseUserProvider struct {
    db *sql.DB
}

func (d *CustomDatabaseUserProvider) GetUserByUsername(username string) (*ginauth.User, error) {
    var user ginauth.User
    query := `SELECT id, username, password_hash FROM users WHERE username = $1`
    
    err := d.db.QueryRow(query, username).Scan(&user.ID, &user.Username, &user.PasswordHash)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, errors.New("user not found")
        }
        return nil, err
    }
    
    return &user, nil
}

// Usage
userProvider := &CustomDatabaseUserProvider{db: db}
authenticator := ginauth.BasicAuthenticator(userProvider)
```

## Bcrypt Password Hashing

### Creating Users with Bcrypt

```go
// Create a single user with bcrypt
user, err := ginauth.CreateUserWithBcrypt(1, "admin", "admin123")
if err != nil {
    log.Fatal(err)
}

// Create multiple users with bcrypt
users, err := ginauth.CreateUserMapWithBcrypt([]struct {
    ID       int
    Username string
    Password string
}{
    {ID: 1, Username: "admin", Password: "admin123"},
    {ID: 2, Username: "user", Password: "user123"},
})
```

### Manual Password Hashing

```go
// Hash a password
hashedPassword, err := ginauth.HashPassword("myPassword")
if err != nil {
    log.Fatal(err)
}

// Check a password against its hash
isValid := ginauth.CheckPasswordHash("myPassword", hashedPassword)
```

## Token Storage

### TokenStorage Interface

```go
type TokenStorage interface {
    StoreToken(tokenID string, token string, expiresAt time.Time) error
    GetToken(tokenID string) (string, error)
    DeleteToken(tokenID string) error
    IsTokenValid(tokenID string) (bool, error)
    RevokeAllUserTokens(userID interface{}) error
}
```

### In-Memory Token Storage

```go
// Create in-memory token storage
tokenStorage := ginauth.NewInMemoryTokenStorage()

// Use with auth middleware
authMiddleware := ginauth.New(ginauth.AuthConfig{
    TokenStorage: tokenStorage,
    // ... other config
})
```

### Custom Token Storage

You can implement your own token storage by implementing the `TokenStorage` interface:

```go
type RedisTokenStorage struct {
    client *redis.Client
}

func (r *RedisTokenStorage) StoreToken(tokenID string, token string, expiresAt time.Time) error {
    return r.client.Set(context.Background(), tokenID, token, time.Until(expiresAt)).Err()
}

func (r *RedisTokenStorage) GetToken(tokenID string) (string, error) {
    return r.client.Get(context.Background(), tokenID).Result()
}

// ... implement other methods
```

## API Endpoints

### Login
```http
POST /login
Content-Type: application/json

{
    "username": "admin",
    "password": "admin123"
}
```

### Logout
```http
POST /logout
Authorization: Bearer <token>
```

### Refresh Token
```http
POST /refresh
Authorization: Bearer <token>
```

### Protected Endpoint
```http
GET /api/profile
Authorization: Bearer <token>
```

## Example Usage

See the `example/` directory for a complete working example.

## Dependencies

- `github.com/gin-gonic/gin` - Web framework
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `golang.org/x/crypto/bcrypt` - Password hashing

## License

MIT
