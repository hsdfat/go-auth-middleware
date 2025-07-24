# ProjectDump Analysis

**Generated on:** 2025-07-24 22:31:28
**Project Path:** .

## Project Summary

- **Primary Language:** JavaScript
- **Total Files:** 30
- **Processed Files:** 26
- **Project Size:** 101.71 KB

## Detected Technologies

### JavaScript (100.0% confidence)
*JavaScript runtime and ecosystem*

**Related files:**
- README.md
- core\bcrypt.go
- core\interfaces.go
- core\storage.go
- core\structs.go
- ... and 16 more files

### CSS (100.0% confidence)
*Cascading Style Sheets*

**Related files:**
- README.md
- core\bcrypt.go
- core\interfaces.go
- core\storage.go
- core\structs.go
- ... and 16 more files

### Java (100.0% confidence)
*Java programming language*

**Related files:**
- README.md
- core\bcrypt.go
- core\interfaces.go
- core\storage.go
- core\structs.go
- ... and 16 more files

### Python (100.0% confidence)
*Python programming language*

**Related files:**
- README.md
- core\bcrypt.go
- core\interfaces.go
- core\storage.go
- core\structs.go
- ... and 17 more files

### Go (100.0% confidence)
*Go programming language*

**Related files:**
- README.md
- core\bcrypt.go
- core\interfaces.go
- core\storage.go
- core\structs.go
- ... and 18 more files

### Ruby (75.0% confidence)
*Ruby programming language*

**Related files:**
- README.md
- core\storage.go
- core\structs.go
- examples\README.md
- examples\basic\main.go
- ... and 10 more files

### TypeScript (60.0% confidence)
*TypeScript - JavaScript with static typing*

**Related files:**
- README.md
- core\interfaces.go
- core\structs.go
- examples\database\main.go
- fiberauth\interfaces.go
- ... and 5 more files

### Docker (50.0% confidence)
*Docker containerization platform*

**Related files:**
- README.md
- core\interfaces.go
- examples\README.md
- examples\database\main.go
- examples\fiber\README.md
- ... and 4 more files

### Rust (45.0% confidence)
*Rust systems programming language*

**Related files:**
- README.md
- examples\README.md
- examples\fiber\README.md
- examples\fiber\config\main.go
- fiberauth\structs.go
- ... and 4 more files

### C (10.0% confidence)
*C programming language*

**Related files:**
- examples\database\main.go
- ginauth\jwt.go

### PHP (10.0% confidence)
*PHP server-side scripting language*

**Related files:**
- examples\database\main.go
- ginauth\jwt.go

## Directory Structure

```
├── .gitignore
├── README.md
├── core
│   ├── bcrypt.go
│   ├── interfaces.go
│   ├── storage.go
│   └── structs.go
├── examples
│   ├── README.md
│   ├── basic
│   │   └── main.go
│   ├── bcrypt
│   │   └── main.go
│   ├── config
│   │   └── main.go
│   ├── database
│   │   └── main.go
│   ├── fiber
│   │   ├── README.md
│   │   ├── basic
│   │   │   └── main.go
│   │   ├── bcrypt
│   │   │   └── main.go
│   │   └── config
│   │       └── main.go
│   └── jwt
│       └── main.go
├── fiberauth
│   ├── bcrypt.go
│   ├── interfaces.go
│   ├── jwt.go
│   └── structs.go
├── ginauth
│   ├── bcrypt.go
│   ├── interfaces.go
│   ├── jwt.go
│   └── structs.go
├── go.mod
└── go.sum
```

## Source Code

### core/

#### core\bcrypt.go
*Language: Go | Size: 887 bytes*

```go
package core

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashToken hashes a token using bcrypt for storage
func HashToken(token string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckTokenHash compares a token with its hash
func CheckTokenHash(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
} 
```

#### core\interfaces.go
*Language: Go | Size: 528 bytes*

```go
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
```

#### core\storage.go
*Language: Go | Size: 1889 bytes*

```go
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
```

#### core\structs.go
*Language: Go | Size: 813 bytes*

```go
package core

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a user for authentication
type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"-"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	PasswordHash string `json:"-"`
}

type MapUserProvider struct {
	users map[string]User
}

type DatabaseUserProvider struct {
	// Add your database connection or client here
}

type tokenData struct {
	token     string
	expiresAt time.Time
}

type InMemoryTokenStorage struct {
	tokens map[string]tokenData
}

// Claims represents JWT claims
type Claims struct {
	UserID   interface{} `json:"user_id"`
	Username string      `json:"username"`
	jwt.RegisteredClaims
}
```

### examples/

#### examples\README.md
*Language: Markdown | Size: 4813 bytes*

```markdown
# Go Auth Middleware Examples

This directory contains various examples demonstrating how to use the Go Auth Middleware.

## Examples Overview

### 1. Basic Example (`basic/`)
- **Port**: 8080
- **Features**: Complete authentication with bcrypt password hashing and token storage
- **Use Case**: Standard web application authentication
- **Run**: `go run examples/basic/main.go`

### 2. Database Example (`database/`)
- **Port**: 8081
- **Features**: Database-based user storage with PostgreSQL
- **Use Case**: Production applications with persistent user data
- **Run**: `go run examples/database/main.go`
- **Note**: Requires PostgreSQL running and connection string configuration

### 3. JWT-Only Example (`jwt/`)
- **Port**: 8082
- **Features**: JWT authentication without bcrypt (plain text passwords)
- **Use Case**: Simple authentication for development/testing
- **Run**: `go run examples/jwt/main.go`

### 4. Bcrypt-Only Example (`bcrypt/`)
- **Port**: 8083
- **Features**: Bcrypt password hashing with utility endpoints
- **Use Case**: Learning bcrypt functionality and password management
- **Run**: `go run examples/bcrypt/main.go`

### 5. Configuration Example (`config/`)
- **Port**: 8084
- **Features**: Demonstrates different token storage configurations
- **Use Case**: Understanding how to configure token storage modes
- **Run**: `go run examples/config/main.go`

## Quick Start

1. **Build the examples**:
   ```bash
   go build ./examples/basic
   go build ./examples/database
   go build ./examples/jwt
   go build ./examples/bcrypt
   go build ./examples/config
   ```

2. **Run any example**:
   ```bash
   # Basic example
   go run examples/basic/main.go
   
   # Database example (requires PostgreSQL)
   go run examples/database/main.go
   
   # JWT-only example
   go run examples/jwt/main.go
   
   # Bcrypt example
   go run examples/bcrypt/main.go
   
   # Configuration example
   go run examples/config/main.go
   ```

## Testing the Examples

### Login
All examples support login via POST request:
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Access Protected Endpoints
Use the token from login response:
```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Bcrypt Utilities (bcrypt example only)
```bash
# Hash a password
curl http://localhost:8083/hash/mypassword

# Check password against hash
curl -X POST http://localhost:8083/check \
  -H "Content-Type: application/json" \
  -d '{"password": "mypassword", "hash": "hashed_value"}'
```

## Default Users

All examples include these default users:
- **Username**: `admin`, **Password**: `admin123`
- **Username**: `user`, **Password**: `user123`

## Database Setup (Database Example)

For the database example, you need:

1. **PostgreSQL running**
2. **Update connection string** in `examples/database/main.go`:
   ```go
   db, err := sql.Open("postgres", "postgres://username:password@localhost/dbname?sslmode=disable")
   ```

3. **Install PostgreSQL driver**:
   ```bash
   go get github.com/lib/pq
   ```

The example will automatically create the `users` table if it doesn't exist.

## Ports Used

- **Basic**: 8080
- **Database**: 8081
- **JWT-Only**: 8082
- **Bcrypt-Only**: 8083
- **Configuration**: 8084

Make sure these ports are available when running the examples.

## Token Storage Configuration

The middleware now supports configurable token storage modes:

### Configuration Options

- **EnableTokenStorage**: Enable/disable token storage (default: true)
- **TokenStorageMode**: How to store tokens
  - `"jwt"`: Store JWT tokens as-is
  - `"bcrypt"`: Store bcrypt hashes of tokens
  - `"both"`: Store both JWT and bcrypt hash
- **StoreTokenOnLogin**: Whether to store tokens on login (default: true)
- **ValidateTokenOnRequest**: Whether to validate tokens from storage on each request (default: true)

### Example Configuration

```go
authMiddleware := ginauth.New(ginauth.AuthConfig{
    SecretKey:    "your-secret-key",
    TokenStorage: tokenStorage,
    UseBcrypt:    true,
    // Token storage configuration
    EnableTokenStorage:    true,
    TokenStorageMode:      "both", // "jwt", "bcrypt", or "both"
    StoreTokenOnLogin:     true,
    ValidateTokenOnRequest: true,
    // ... other config
})
```

### Use Cases

- **JWT Mode**: Standard JWT authentication with token storage
- **Bcrypt Mode**: Enhanced security by storing hashed tokens
- **Both Mode**: Maximum security with both JWT and hash validation
- **No Storage**: Traditional JWT without server-side storage 
```

### examples\basic/

#### examples\basic\main.go
*Language: Go | Size: 2073 bytes*

```go
package main

import (
	"log"
	"net/http"

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

	// Create auth middleware with bcrypt and token storage
	authMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         24 * 60 * 60, // 24 hours
		MaxRefresh:      24 * 60 * 60, // 24 hours
		TokenStorage:    tokenStorage,
		UseBcrypt:       true,
		Authenticator:   ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:     ginauth.BasicPayloadFunc(),
		IdentityHandler: ginauth.BasicIdentityHandler(),
	})

	// Public routes
	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
	r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected profile endpoint",
				"user_id": userID,
			})
		})

		protected.GET("/dashboard", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Welcome to dashboard",
			})
		})
	}

	log.Println("Basic example server starting on :8080")
	log.Println("Try logging in with:")
	log.Println("  POST /login")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8080"))
}
```

### examples\bcrypt/

#### examples\bcrypt\main.go
*Language: Go | Size: 2992 bytes*

```go
package main

import (
	"log"
	"net/http"

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

	// Create auth middleware with bcrypt
	authMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         24 * 60 * 60, // 24 hours
		MaxRefresh:      24 * 60 * 60, // 24 hours
		TokenStorage:    tokenStorage,
		UseBcrypt:       true, // Enable bcrypt for this example
		Authenticator:   ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:     ginauth.BasicPayloadFunc(),
		IdentityHandler: ginauth.BasicIdentityHandler(),
	})

	// Public routes
	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
	r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

	// Bcrypt utility endpoints
	r.GET("/hash/:password", func(c *gin.Context) {
		password := c.Param("password")
		hash, err := ginauth.HashPassword(password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"password": password,
			"hash":     hash,
		})
	})

	r.POST("/check", func(c *gin.Context) {
		var req struct {
			Password string `json:"password"`
			Hash     string `json:"hash"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		isValid := ginauth.CheckPasswordHash(req.Password, req.Hash)
		c.JSON(http.StatusOK, gin.H{
			"password": req.Password,
			"hash":     req.Hash,
			"valid":    isValid,
		})
	})

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected profile endpoint",
				"user_id": userID,
			})
		})
	}

	log.Println("Bcrypt example server starting on :8083")
	log.Println("This example demonstrates bcrypt password hashing")
	log.Println("Try these endpoints:")
	log.Println("  GET  /hash/admin123 - Hash a password")
	log.Println("  POST /check - Check password against hash")
	log.Println("  POST /login - Login with bcrypt hashed passwords")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8083"))
}
```

### examples\config/

#### examples\config\main.go
*Language: Go | Size: 6230 bytes*

```go
package main

import (
	"log"
	"net/http"

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

	// Example 1: JWT-only token storage
	jwtAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "jwt-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// JWT-only configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "jwt",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 2: Bcrypt token storage
	bcryptAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "bcrypt-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// Bcrypt-only configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "bcrypt",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 3: Both JWT and Bcrypt token storage
	bothAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "both-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// Both JWT and Bcrypt configuration
		EnableTokenStorage:     true,
		TokenStorageMode:       "both",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// Example 4: No token storage
	noStorageAuthMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:    "no-storage-secret-key",
		Timeout:      24 * 60 * 60, // 24 hours
		MaxRefresh:   24 * 60 * 60, // 24 hours
		TokenStorage: tokenStorage,
		UseBcrypt:    true,
		// No token storage configuration
		EnableTokenStorage:     false,
		TokenStorageMode:       "jwt",
		StoreTokenOnLogin:      false,
		ValidateTokenOnRequest: false,
		Authenticator:          ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:            ginauth.BasicPayloadFunc(),
		IdentityHandler:        ginauth.BasicIdentityHandler(),
	})

	// JWT-only routes
	jwtGroup := r.Group("/jwt")
	{
		jwtGroup.POST("/login", jwtAuthMiddleware.LoginHandler)
		jwtGroup.POST("/logout", jwtAuthMiddleware.MiddlewareFunc(), jwtAuthMiddleware.LogoutHandler)
		jwtGroup.POST("/refresh", jwtAuthMiddleware.MiddlewareFunc(), jwtAuthMiddleware.RefreshHandler)
		jwtGroup.GET("/profile", jwtAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "JWT-only protected endpoint",
				"user_id": userID,
				"mode":    "jwt",
			})
		})
	}

	// Bcrypt-only routes
	bcryptGroup := r.Group("/bcrypt")
	{
		bcryptGroup.POST("/login", bcryptAuthMiddleware.LoginHandler)
		bcryptGroup.POST("/logout", bcryptAuthMiddleware.MiddlewareFunc(), bcryptAuthMiddleware.LogoutHandler)
		bcryptGroup.POST("/refresh", bcryptAuthMiddleware.MiddlewareFunc(), bcryptAuthMiddleware.RefreshHandler)
		bcryptGroup.GET("/profile", bcryptAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Bcrypt-only protected endpoint",
				"user_id": userID,
				"mode":    "bcrypt",
			})
		})
	}

	// Both JWT and Bcrypt routes
	bothGroup := r.Group("/both")
	{
		bothGroup.POST("/login", bothAuthMiddleware.LoginHandler)
		bothGroup.POST("/logout", bothAuthMiddleware.MiddlewareFunc(), bothAuthMiddleware.LogoutHandler)
		bothGroup.POST("/refresh", bothAuthMiddleware.MiddlewareFunc(), bothAuthMiddleware.RefreshHandler)
		bothGroup.GET("/profile", bothAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Both JWT and Bcrypt protected endpoint",
				"user_id": userID,
				"mode":    "both",
			})
		})
	}

	// No storage routes
	noStorageGroup := r.Group("/no-storage")
	{
		noStorageGroup.POST("/login", noStorageAuthMiddleware.LoginHandler)
		noStorageGroup.POST("/logout", noStorageAuthMiddleware.MiddlewareFunc(), noStorageAuthMiddleware.LogoutHandler)
		noStorageGroup.POST("/refresh", noStorageAuthMiddleware.MiddlewareFunc(), noStorageAuthMiddleware.RefreshHandler)
		noStorageGroup.GET("/profile", noStorageAuthMiddleware.MiddlewareFunc(), func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "No storage protected endpoint",
				"user_id": userID,
				"mode":    "no-storage",
			})
		})
	}

	log.Println("Configuration example server starting on :8084")
	log.Println("Available endpoints:")
	log.Println("  JWT-only:     POST /jwt/login, GET /jwt/profile")
	log.Println("  Bcrypt-only:  POST /bcrypt/login, GET /bcrypt/profile")
	log.Println("  Both:         POST /both/login, GET /both/profile")
	log.Println("  No storage:   POST /no-storage/login, GET /no-storage/profile")
	log.Println("Try logging in with:")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8084"))
}
```

### examples\database/

#### examples\database\main.go
*Language: Go | Size: 4065 bytes*

```go
package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/ginauth"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// CustomDatabaseUserProvider implements UserProvider for database
type CustomDatabaseUserProvider struct {
	db *sql.DB
}

// NewCustomDatabaseUserProvider creates a new database user provider
func NewCustomDatabaseUserProvider(db *sql.DB) *CustomDatabaseUserProvider {
	return &CustomDatabaseUserProvider{db: db}
}

// GetUserByUsername retrieves a user by username from the database
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

// Example function to initialize database and create tables
func initDatabase() (*sql.DB, error) {
	// Connect to database (replace with your connection string)
	db, err := sql.Open("postgres", "postgres://username:password@localhost/dbname?sslmode=disable")
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Create users table if it doesn't exist
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`

	_, err = db.Exec(createTableQuery)
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Example function to create a user in the database
func createUserInDatabase(db *sql.DB, username, password string) error {
	// Hash the password
	hashedPassword, err := ginauth.HashPassword(password)
	if err != nil {
		return err
	}

	// Insert user into database
	query := `INSERT INTO users (username, password_hash) VALUES ($1, $2)`
	_, err = db.Exec(query, username, hashedPassword)
	return err
}

func main() {
	// Initialize database
	db, err := initDatabase()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Create a test user in the database
	err = createUserInDatabase(db, "admin", "admin123")
	if err != nil {
		log.Printf("Failed to create user (might already exist): %v", err)
	}

	// Create user provider
	userProvider := NewCustomDatabaseUserProvider(db)

	// Create token storage
	tokenStorage := ginauth.NewInMemoryTokenStorage()

	// Create auth middleware
	authMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         24 * 60 * 60, // 24 hours
		MaxRefresh:      24 * 60 * 60, // 24 hours
		TokenStorage:    tokenStorage,
		UseBcrypt:       true,
		Authenticator:   ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:     ginauth.BasicPayloadFunc(),
		IdentityHandler: ginauth.BasicIdentityHandler(),
	})

	// Setup routes
	r := gin.Default()

	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
	r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected profile endpoint",
				"user_id": userID,
			})
		})
	}

	log.Println("Database example server starting on :8081")
	log.Println("Note: Make sure PostgreSQL is running and update the connection string")
	log.Println("Try logging in with:")
	log.Println("  POST /login")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8081"))
}
```

### examples\fiber/

#### examples\fiber\README.md
*Language: Markdown | Size: 2854 bytes*

```markdown
# Fiber Authentication Examples

This directory contains examples of how to use the Fiber authentication middleware.

## Examples

### Basic Example (`basic/`)
A simple authentication example with JWT tokens and in-memory token storage.

**Features:**
- JWT token authentication
- In-memory token storage
- Basic user authentication
- Protected routes

**Usage:**
```bash
cd examples/fiber/basic
go run main.go
```

**Test with:**
```bash
# Login
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Access protected route
curl -X GET http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### Bcrypt Example (`bcrypt/`)
Authentication example using bcrypt for password hashing and token storage.

**Features:**
- Bcrypt password hashing
- Bcrypt token storage
- Enhanced security
- Pre-hashed passwords

**Usage:**
```bash
cd examples/fiber/bcrypt
go run main.go
```

**Test with:**
```bash
# Login (passwords are pre-hashed)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Configuration Example (`config/`)
Advanced example demonstrating different configuration options for token storage.

**Features:**
- Configurable token storage modes
- Both JWT and bcrypt support
- Flexible authentication options
- Comprehensive configuration

**Usage:**
```bash
cd examples/fiber/config
go run main.go
```

## Configuration Options

The Fiber authentication middleware supports various configuration options:

### Token Storage Modes
- `"jwt"`: Store tokens as plain JWT
- `"bcrypt"`: Hash tokens with bcrypt before storage
- `"both"`: Use both JWT and bcrypt validation

### Key Configuration Fields
- `EnableTokenStorage`: Enable/disable token storage
- `TokenStorageMode`: Choose storage mode
- `StoreTokenOnLogin`: Store token when user logs in
- `ValidateTokenOnRequest`: Validate token on each request
- `UseBcrypt`: Enable bcrypt for password hashing

## API Endpoints

All examples provide the following endpoints:

- `POST /login` - User login
- `POST /logout` - User logout
- `POST /refresh` - Refresh token
- `GET /protected` - Protected route (requires authentication)
- `GET /public` - Public route

## Testing

You can test the examples using curl or any HTTP client:

1. **Login** to get a token
2. **Use the token** in the Authorization header for protected routes
3. **Refresh** the token when needed
4. **Logout** to invalidate the token

## Security Features

- JWT token validation
- Token storage and revocation
- Bcrypt password hashing
- Configurable token expiration
- Secure cookie handling
- Token refresh mechanism 
```

### examples\fiber\basic/

#### examples\fiber\basic\main.go
*Language: Go | Size: 3858 bytes*

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/fiberauth"
)

func main() {
	app := fiber.New()

	// Create user provider with sample users
	users := map[string]fiberauth.User{
		"admin": {
			ID:       1,
			Username: "admin",
			Password: "admin123",
		},
		"user": {
			ID:       2,
			Username: "user",
			Password: "user123",
		},
	}
	userProvider := fiberauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := fiberauth.NewInMemoryTokenStorage()

	// Create authentication middleware
	authMiddleware := fiberauth.NewFiberAuthMiddleware(fiberauth.AuthConfig{
		SecretKey:              "your-secret-key",
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		TokenLookup:            "header:Authorization",
		TokenHeadName:          "Bearer",
		Authenticator:          authenticator(userProvider),
		Authorizator:           authorizator,
		Unauthorized:           unauthorized,
		LoginResponse:          loginResponse,
		LogoutResponse:         logoutResponse,
		RefreshResponse:        refreshResponse,
		TokenStorage:           tokenStorage,
		EnableTokenStorage:     true,
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
	})

	// Public routes
	app.Post("/login", authMiddleware.LoginHandler())
	app.Post("/logout", authMiddleware.LogoutHandler())
	app.Post("/refresh", authMiddleware.RefreshHandler())

	// Protected routes
	protected := app.Group("/protected")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.Get("/", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "This is a protected route",
				"user_id": c.Locals("identity"),
			})
		})
	}

	// Public route
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a public route",
		})
	})

	log.Fatal(app.Listen(":3000"))
}

// authenticator validates user credentials
func authenticator(userProvider fiberauth.UserProvider) func(c *fiber.Ctx) (interface{}, error) {
	return func(c *fiber.Ctx) (interface{}, error) {
		var login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&login); err != nil {
			return nil, err
		}

		user, err := userProvider.GetUserByUsername(login.Username)
		if err != nil {
			return nil, err
		}

		if user.Password != login.Password {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		return jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// authorizator checks if user has permission to access the resource
func authorizator(data interface{}, c *fiber.Ctx) bool {
	if userID, ok := data.(int); ok {
		// Simple authorization: allow all authenticated users
		return userID > 0
	}
	return false
}

// unauthorized handles unauthorized requests
func unauthorized(c *fiber.Ctx, code int, message string) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": message,
	})
}

// loginResponse handles login response
func loginResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}

// logoutResponse handles logout response
func logoutResponse(c *fiber.Ctx, code int) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": "Successfully logged out",
	})
}

// refreshResponse handles refresh response
func refreshResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}
```

### examples\fiber\bcrypt/

#### examples\fiber\bcrypt\main.go
*Language: Go | Size: 4206 bytes*

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/fiberauth"
)

func main() {
	app := fiber.New()

	// Create user provider with sample users (passwords are hashed)
	users := map[string]fiberauth.User{
		"admin": {
			ID:           1,
			Username:     "admin",
			PasswordHash: "$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVEFDa", // admin123
		},
		"user": {
			ID:           2,
			Username:     "user",
			PasswordHash: "$2a$10$8K1p/a0dL1LXMIgoEDFrwOfgqwAGcwZQh3UPHz9xqxk3VlqH3qKqC", // user123
		},
	}
	userProvider := fiberauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := fiberauth.NewInMemoryTokenStorage()

	// Create authentication middleware with bcrypt
	authMiddleware := fiberauth.NewFiberAuthMiddleware(fiberauth.AuthConfig{
		SecretKey:              "your-secret-key",
		Timeout:                time.Hour,
		MaxRefresh:             time.Hour * 24,
		TokenLookup:            "header:Authorization",
		TokenHeadName:          "Bearer",
		Authenticator:          authenticator(userProvider),
		Authorizator:           authorizator,
		Unauthorized:           unauthorized,
		LoginResponse:          loginResponse,
		LogoutResponse:         logoutResponse,
		RefreshResponse:        refreshResponse,
		TokenStorage:           tokenStorage,
		UseBcrypt:              true,
		EnableTokenStorage:     true,
		TokenStorageMode:       "bcrypt",
		StoreTokenOnLogin:      true,
		ValidateTokenOnRequest: true,
	})

	// Public routes
	app.Post("/login", authMiddleware.LoginHandler())
	app.Post("/logout", authMiddleware.LogoutHandler())
	app.Post("/refresh", authMiddleware.RefreshHandler())

	// Protected routes
	protected := app.Group("/protected")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.Get("/", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "This is a protected route with bcrypt",
				"user_id": c.Locals("identity"),
			})
		})
	}

	// Public route
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a public route",
		})
	})

	log.Fatal(app.Listen(":3000"))
}

// authenticator validates user credentials using bcrypt
func authenticator(userProvider fiberauth.UserProvider) func(c *fiber.Ctx) (interface{}, error) {
	return func(c *fiber.Ctx) (interface{}, error) {
		var login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&login); err != nil {
			return nil, err
		}

		user, err := userProvider.GetUserByUsername(login.Username)
		if err != nil {
			return nil, err
		}

		// Check password using bcrypt
		if !fiberauth.CheckPasswordHash(login.Password, user.PasswordHash) {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		return jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// authorizator checks if user has permission to access the resource
func authorizator(data interface{}, c *fiber.Ctx) bool {
	if userID, ok := data.(int); ok {
		// Simple authorization: allow all authenticated users
		return userID > 0
	}
	return false
}

// unauthorized handles unauthorized requests
func unauthorized(c *fiber.Ctx, code int, message string) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": message,
	})
}

// loginResponse handles login response
func loginResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}

// logoutResponse handles logout response
func logoutResponse(c *fiber.Ctx, code int) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": "Successfully logged out",
	})
}

// refreshResponse handles refresh response
func refreshResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}
```

### examples\fiber\config/

#### examples\fiber\config\main.go
*Language: Go | Size: 4033 bytes*

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/fiberauth"
)

func main() {
	app := fiber.New()

	// Create user provider with sample users
	users := map[string]fiberauth.User{
		"admin": {
			ID:       1,
			Username: "admin",
			Password: "admin123",
		},
		"user": {
			ID:       2,
			Username: "user",
			Password: "user123",
		},
	}
	userProvider := fiberauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := fiberauth.NewInMemoryTokenStorage()

	// Create authentication middleware with different configurations
	authMiddleware := fiberauth.NewFiberAuthMiddleware(fiberauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         time.Hour,
		MaxRefresh:      time.Hour * 24,
		TokenLookup:     "header:Authorization",
		TokenHeadName:   "Bearer",
		Authenticator:   authenticator(userProvider),
		Authorizator:    authorizator,
		Unauthorized:    unauthorized,
		LoginResponse:   loginResponse,
		LogoutResponse:  logoutResponse,
		RefreshResponse: refreshResponse,
		TokenStorage:    tokenStorage,
		UseBcrypt:       true,
		// Token storage configuration
		EnableTokenStorage:     true,   // Enable token storage
		TokenStorageMode:       "both", // Use both JWT and bcrypt
		StoreTokenOnLogin:      true,   // Store token on login
		ValidateTokenOnRequest: true,   // Validate token on each request
	})

	// Public routes
	app.Post("/login", authMiddleware.LoginHandler())
	app.Post("/logout", authMiddleware.LogoutHandler())
	app.Post("/refresh", authMiddleware.RefreshHandler())

	// Protected routes
	protected := app.Group("/protected")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.Get("/", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"message": "This is a protected route with configuration",
				"user_id": c.Locals("identity"),
			})
		})
	}

	// Public route
	app.Get("/public", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is a public route",
		})
	})

	log.Fatal(app.Listen(":3000"))
}

// authenticator validates user credentials
func authenticator(userProvider fiberauth.UserProvider) func(c *fiber.Ctx) (interface{}, error) {
	return func(c *fiber.Ctx) (interface{}, error) {
		var login struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.BodyParser(&login); err != nil {
			return nil, err
		}

		user, err := userProvider.GetUserByUsername(login.Username)
		if err != nil {
			return nil, err
		}

		if user.Password != login.Password {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
		}

		return jwt.MapClaims{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// authorizator checks if user has permission to access the resource
func authorizator(data interface{}, c *fiber.Ctx) bool {
	if userID, ok := data.(int); ok {
		// Simple authorization: allow all authenticated users
		return userID > 0
	}
	return false
}

// unauthorized handles unauthorized requests
func unauthorized(c *fiber.Ctx, code int, message string) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": message,
	})
}

// loginResponse handles login response
func loginResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}

// logoutResponse handles logout response
func logoutResponse(c *fiber.Ctx, code int) {
	c.Status(code).JSON(fiber.Map{
		"code":    code,
		"message": "Successfully logged out",
	})
}

// refreshResponse handles refresh response
func refreshResponse(c *fiber.Ctx, code int, token string, expire time.Time) {
	c.Status(code).JSON(fiber.Map{
		"code":   code,
		"token":  token,
		"expire": expire.Format(time.RFC3339),
	})
}
```

### examples\jwt/

#### examples\jwt\main.go
*Language: Go | Size: 2137 bytes*

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hsdfat/go-auth-middleware/ginauth"
)

func main() {
	r := gin.Default()

	// Create simple users without bcrypt (plain text passwords)
	users := map[string]ginauth.User{
		"admin": {
			ID:       1,
			Username: "admin",
			Password: "admin123", // Plain text password
		},
		"user": {
			ID:       2,
			Username: "user",
			Password: "user123", // Plain text password
		},
	}

	// Create user provider
	userProvider := ginauth.NewMapUserProvider(users)

	// Create token storage
	tokenStorage := ginauth.NewInMemoryTokenStorage()

	// Create auth middleware without bcrypt
	authMiddleware := ginauth.New(ginauth.AuthConfig{
		SecretKey:       "your-secret-key",
		Timeout:         24 * 60 * 60, // 24 hours
		MaxRefresh:      24 * 60 * 60, // 24 hours
		TokenStorage:    tokenStorage,
		UseBcrypt:       false, // No bcrypt for this example
		Authenticator:   ginauth.BasicAuthenticator(userProvider),
		PayloadFunc:     ginauth.BasicPayloadFunc(),
		IdentityHandler: ginauth.BasicIdentityHandler(),
	})

	// Public routes
	r.POST("/login", authMiddleware.LoginHandler)
	r.POST("/logout", authMiddleware.MiddlewareFunc(), authMiddleware.LogoutHandler)
	r.POST("/refresh", authMiddleware.MiddlewareFunc(), authMiddleware.RefreshHandler)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMiddleware.MiddlewareFunc())
	{
		protected.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("identity")
			c.JSON(http.StatusOK, gin.H{
				"message": "Protected profile endpoint",
				"user_id": userID,
			})
		})

		protected.GET("/dashboard", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "Welcome to dashboard",
			})
		})
	}

	log.Println("JWT-only example server starting on :8082")
	log.Println("This example uses plain text passwords (no bcrypt)")
	log.Println("Try logging in with:")
	log.Println("  POST /login")
	log.Println("  Body: {\"username\": \"admin\", \"password\": \"admin123\"}")
	log.Fatal(r.Run(":8082"))
}
```

### fiberauth/

#### fiberauth\bcrypt.go
*Language: Go | Size: 312 bytes*

```go
package fiberauth

import "github.com/hsdfat/go-auth-middleware/core"

// Re-export core bcrypt functions for backward compatibility
var (
	HashPassword      = core.HashPassword
	CheckPasswordHash = core.CheckPasswordHash
	HashToken         = core.HashToken
	CheckTokenHash    = core.CheckTokenHash
)
```

#### fiberauth\interfaces.go
*Language: Go | Size: 210 bytes*

```go
package fiberauth

import "github.com/hsdfat/go-auth-middleware/core"

// Re-export core interfaces for backward compatibility
type TokenStorage = core.TokenStorage
type UserProvider = core.UserProvider
```

#### fiberauth\jwt.go
*Language: Go | Size: 12707 bytes*

```go
package fiberauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// NewFiberAuthMiddleware creates a new FiberAuthMiddleware instance
func NewFiberAuthMiddleware(config AuthConfig) *FiberAuthMiddleware {
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = time.Hour
	}
	if config.MaxRefresh == 0 {
		config.MaxRefresh = time.Hour * 24
	}
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.TokenHeadName == "" {
		config.TokenHeadName = "Bearer"
	}
	if config.Realm == "" {
		config.Realm = "jwt auth"
	}
	if config.IdentityKey == "" {
		config.IdentityKey = "identity"
	}
	if config.IdentityHandler == nil {
		config.IdentityHandler = func(c *fiber.Ctx) interface{} {
			claims := c.Locals("JWT_PAYLOAD")
			if claims == nil {
				return nil
			}
			if mapClaims, ok := claims.(jwt.MapClaims); ok {
				if userID, exists := mapClaims["user_id"]; exists {
					return userID
				}
			}
			return nil
		}
	}
	if config.PayloadFunc == nil {
		config.PayloadFunc = func(data interface{}) jwt.MapClaims {
			if mapClaims, ok := data.(jwt.MapClaims); ok {
				return mapClaims
			}
			return jwt.MapClaims{}
		}
	}
	if config.Unauthorized == nil {
		config.Unauthorized = func(c *fiber.Ctx, code int, message string) {
			c.Status(code).JSON(fiber.Map{
				"code":    code,
				"message": message,
			})
		}
	}
	if config.LoginResponse == nil {
		config.LoginResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) {
			c.Status(code).JSON(fiber.Map{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}
	if config.LogoutResponse == nil {
		config.LogoutResponse = func(c *fiber.Ctx, code int) {
			c.Status(code).JSON(fiber.Map{
				"code":    code,
				"message": "Successfully logged out",
			})
		}
	}
	if config.RefreshResponse == nil {
		config.RefreshResponse = func(c *fiber.Ctx, code int, token string, expire time.Time) {
			c.Status(code).JSON(fiber.Map{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	return &FiberAuthMiddleware{
		Config: config,
	}
}

// MiddlewareFunc returns the middleware function
func (m *FiberAuthMiddleware) MiddlewareFunc() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Parse token
		token, err := m.parseToken(c)
		if err != nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, err.Error())
			return nil
		}

		// Validate token
		if m.Config.ValidateTokenOnRequest && m.Config.TokenStorage != nil {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token claims")
				return nil
			}

			tokenID, ok := claims["jti"].(string)
			if !ok {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing token ID")
				return nil
			}

			// Check if token is stored and valid
			isValid, err := m.Config.TokenStorage.IsTokenValid(tokenID)
			if err != nil || !isValid {
				m.Config.Unauthorized(c, http.StatusUnauthorized, "Token not found or invalid")
				return nil
			}

			// If using bcrypt mode, validate the stored hash
			if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
				storedToken, err := m.Config.TokenStorage.GetToken(tokenID)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Token not found in storage")
					return nil
				}

				// Extract the actual token string from the JWT
				tokenString := c.Get("Authorization")
				if tokenString == "" {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing authorization header")
					return nil
				}
				tokenString = strings.TrimPrefix(tokenString, "Bearer ")

				if !CheckTokenHash(tokenString, storedToken) {
					m.Config.Unauthorized(c, http.StatusUnauthorized, "Token hash validation failed")
					return nil
				}
			}
		}

		// Set claims in context
		c.Locals("JWT_PAYLOAD", token.Claims)
		c.Locals("JWT_TOKEN", token)

		// Check authorization
		if m.Config.Authorizator != nil {
			identity := m.Config.IdentityHandler(c)
			if !m.Config.Authorizator(identity, c) {
				m.Config.Unauthorized(c, http.StatusForbidden, "You don't have permission to access this resource")
				return nil
			}
		}

		return c.Next()
	}
}

// LoginHandler handles user login
func (m *FiberAuthMiddleware) LoginHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m.Config.Authenticator == nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Missing authenticator")
			return nil
		}

		data, err := m.Config.Authenticator(c)
		if err != nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, err.Error())
			return nil
		}

		// Generate token
		token := jwt.New(jwt.GetSigningMethod("HS256"))
		now := m.Config.TimeFunc()
		expire := now.Add(m.Config.Timeout)

		// Generate unique token ID
		tokenID, err := generateTokenID()
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to generate token ID")
			return nil
		}

		// Set claims
		claims := m.Config.PayloadFunc(data)
		claims["jti"] = tokenID
		claims["exp"] = expire.Unix()
		claims["orig_iat"] = now.Unix()
		token.Claims = claims

		// Sign token
		tokenString, err := token.SignedString([]byte(m.Config.SecretKey))
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to sign token")
			return nil
		}

		// Store token if enabled
		if m.Config.EnableTokenStorage && m.Config.StoreTokenOnLogin && m.Config.TokenStorage != nil {
			var tokenToStore string
			if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
				// Hash the token for storage
				hashedToken, err := HashToken(tokenString)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to hash token")
					return nil
				}
				tokenToStore = hashedToken
			} else {
				tokenToStore = tokenString
			}

			err = m.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
			if err != nil {
				m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to store token")
				return nil
			}
		}

		// Set cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    tokenString,
				MaxAge:   m.Config.CookieMaxAge,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.LoginResponse(c, http.StatusOK, tokenString, expire)
		return nil
	}
}

// LogoutHandler handles user logout
func (m *FiberAuthMiddleware) LogoutHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from context
		token := c.Locals("JWT_TOKEN")
		if token == nil {
			m.Config.LogoutResponse(c, http.StatusOK)
			return nil
		}

		// Extract token ID and revoke from storage
		if m.Config.TokenStorage != nil {
			if jwtToken, ok := token.(*jwt.Token); ok {
				if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
					if tokenID, ok := claims["jti"].(string); ok {
						m.Config.TokenStorage.DeleteToken(tokenID)
					}
				}
			}
		}

		// Clear cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    "",
				MaxAge:   -1,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.LogoutResponse(c, http.StatusOK)
		return nil
	}
}

// RefreshHandler handles token refresh
func (m *FiberAuthMiddleware) RefreshHandler() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get token from context
		token := c.Locals("JWT_TOKEN")
		if token == nil {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Missing token")
			return nil
		}

		jwtToken, ok := token.(*jwt.Token)
		if !ok {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token")
			return nil
		}

		claims, ok := jwtToken.Claims.(jwt.MapClaims)
		if !ok {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Invalid token claims")
			return nil
		}

		// Check if token can be refreshed
		origIat := int64(claims["orig_iat"].(float64))
		if origIat < m.Config.TimeFunc().Add(-m.Config.MaxRefresh).Unix() {
			m.Config.Unauthorized(c, http.StatusUnauthorized, "Token refresh period expired")
			return nil
		}

		// Generate new token
		newToken := jwt.New(jwt.GetSigningMethod("HS256"))
		now := m.Config.TimeFunc()
		expire := now.Add(m.Config.Timeout)

		// Generate new token ID
		newTokenID, err := generateTokenID()
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to generate token ID")
			return nil
		}

		// Set new claims
		newClaims := jwt.MapClaims{}
		for key, value := range claims {
			if key != "jti" && key != "exp" && key != "orig_iat" {
				newClaims[key] = value
			}
		}
		newClaims["jti"] = newTokenID
		newClaims["exp"] = expire.Unix()
		newClaims["orig_iat"] = now.Unix()
		newToken.Claims = newClaims

		// Sign new token
		newTokenString, err := newToken.SignedString([]byte(m.Config.SecretKey))
		if err != nil {
			m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to sign token")
			return nil
		}

		// Update token storage
		if m.Config.TokenStorage != nil {
			oldTokenID := claims["jti"].(string)
			m.Config.TokenStorage.DeleteToken(oldTokenID)

			if m.Config.EnableTokenStorage {
				var tokenToStore string
				if m.Config.TokenStorageMode == "bcrypt" || m.Config.TokenStorageMode == "both" {
					hashedToken, err := HashToken(newTokenString)
					if err != nil {
						m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to hash token")
						return nil
					}
					tokenToStore = hashedToken
				} else {
					tokenToStore = newTokenString
				}

				err = m.Config.TokenStorage.StoreToken(newTokenID, tokenToStore, expire)
				if err != nil {
					m.Config.Unauthorized(c, http.StatusInternalServerError, "Failed to store token")
					return nil
				}
			}
		}

		// Update cookie if enabled
		if m.Config.SendCookie {
			c.Cookie(&fiber.Cookie{
				Name:     m.Config.CookieName,
				Value:    newTokenString,
				MaxAge:   m.Config.CookieMaxAge,
				Path:     "/",
				Domain:   m.Config.CookieDomain,
				HTTPOnly: m.Config.CookieHTTPOnly,
				SameSite: m.Config.CookieSameSite,
			})
		}

		m.Config.RefreshResponse(c, http.StatusOK, newTokenString, expire)
		return nil
	}
}

// parseToken extracts and validates the JWT token from the request
func (m *FiberAuthMiddleware) parseToken(c *fiber.Ctx) (*jwt.Token, error) {
	var tokenString string

	// Parse token from different sources
	parts := strings.Split(m.Config.TokenLookup, ":")
	switch parts[0] {
	case "header":
		tokenString = c.Get(parts[1])
		if tokenString != "" && m.Config.TokenHeadName != "" {
			tokenString = strings.TrimPrefix(tokenString, m.Config.TokenHeadName+" ")
		}
	case "query":
		tokenString = c.Query(parts[1])
	case "cookie":
		tokenString = c.Cookies(parts[1])
	case "param":
		tokenString = c.Params(parts[1])
	}

	if tokenString == "" {
		return nil, fmt.Errorf("token not found")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.Config.SecretKey), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

// generateTokenID generates a unique token ID
func generateTokenID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// NewMapUserProvider creates a new MapUserProvider
func NewMapUserProvider(users map[string]User) *MapUserProvider {
	return core.NewMapUserProvider(users)
}

// NewInMemoryTokenStorage creates a new InMemoryTokenStorage
func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return core.NewInMemoryTokenStorage()
}
```

#### fiberauth\structs.go
*Language: Go | Size: 1802 bytes*

```go
package fiberauth

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Re-export core types for backward compatibility
type User = core.User
type MapUserProvider = core.MapUserProvider
type DatabaseUserProvider = core.DatabaseUserProvider
type InMemoryTokenStorage = core.InMemoryTokenStorage
type Claims = core.Claims

// AuthConfig holds configuration for the authentication middleware
type AuthConfig struct {
	SecretKey       string
	TokenLookup     string
	TokenHeadName   string
	Realm           string
	IdentityKey     string
	IdentityHandler func(c *fiber.Ctx) interface{}
	Authenticator   func(c *fiber.Ctx) (interface{}, error)
	Authorizator    func(data interface{}, c *fiber.Ctx) bool
	PayloadFunc     func(data interface{}) jwt.MapClaims
	Unauthorized    func(c *fiber.Ctx, code int, message string)
	LoginResponse   func(c *fiber.Ctx, code int, token string, expire time.Time)
	LogoutResponse  func(c *fiber.Ctx, code int)
	RefreshResponse func(c *fiber.Ctx, code int, token string, expire time.Time)
	TimeFunc        func() time.Time
	Timeout         time.Duration
	MaxRefresh      time.Duration
	SendCookie      bool
	CookieName      string
	CookieMaxAge    int
	CookieDomain    string
	CookieHTTPOnly  bool
	CookieSameSite  string
	TokenStorage    TokenStorage
	UseBcrypt       bool
	// Token storage configuration
	EnableTokenStorage     bool   // Whether to use token storage
	TokenStorageMode       string // "jwt", "bcrypt", or "both"
	StoreTokenOnLogin      bool   // Whether to store token on login
	ValidateTokenOnRequest bool   // Whether to validate token from storage on each request
}

type FiberAuthMiddleware struct {
	Config AuthConfig
}
```

### ginauth/

#### ginauth\bcrypt.go
*Language: Go | Size: 3722 bytes*

```go
package ginauth

import (
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Re-export core bcrypt functions for backward compatibility
var (
	HashPassword      = core.HashPassword
	CheckPasswordHash = core.CheckPasswordHash
	HashToken         = core.HashToken
	CheckTokenHash    = core.CheckTokenHash
)

// CreateUserWithBcrypt creates a new user with bcrypt password hashing
func CreateUserWithBcrypt(id int, username, password string) (*User, error) {
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	return &User{
		ID:           id,
		Username:     username,
		PasswordHash: hashedPassword,
	}, nil
}

// CreateUserMapWithBcrypt creates a map of users with bcrypt password hashing
func CreateUserMapWithBcrypt(users []struct {
	ID       int
	Username string
	Password string
}) (map[string]User, error) {
	userMap := make(map[string]User)
	for _, userData := range users {
		user, err := CreateUserWithBcrypt(userData.ID, userData.Username, userData.Password)
		if err != nil {
			return nil, err
		}
		userMap[user.Username] = *user
	}
	return userMap, nil
}

// NewMapUserProvider creates a new map-based user provider
func NewMapUserProvider(users map[string]User) *MapUserProvider {
	return core.NewMapUserProvider(users)
}

// NewDatabaseUserProvider creates a new database-based user provider
func NewDatabaseUserProvider() *DatabaseUserProvider {
	return &DatabaseUserProvider{}
}

// BasicAuthenticator creates a basic authenticator using UserProvider
func BasicAuthenticator(userProvider UserProvider) func(*gin.Context) (*User, interface{}, error) {
	return func(c *gin.Context) (*User, interface{}, error) {
		var loginVals struct {
			Username string `json:"username" binding:"required"`
			Password string `json:"password" binding:"required"`
		}

		if err := c.ShouldBindJSON(&loginVals); err != nil {
			return nil, nil, err
		}

		user, err := userProvider.GetUserByUsername(loginVals.Username)
		if err != nil {
			return nil, nil, errors.New("invalid username or password")
		}

		// Check password - support both plain text and bcrypt
		passwordValid := false
		if user.PasswordHash != "" {
			// Use bcrypt hash
			passwordValid = CheckPasswordHash(loginVals.Password, user.PasswordHash)
		} else if user.Password != "" {
			// Fallback to plain text (for backward compatibility)
			passwordValid = user.Password == loginVals.Password
		}

		if !passwordValid {
			return nil, nil, errors.New("invalid username or password")
		}

		return user, map[string]interface{}{
			"user_id":  user.ID,
			"username": user.Username,
		}, nil
	}
}

// LegacyBasicAuthenticator maintains backward compatibility with map-based authentication
func LegacyBasicAuthenticator(users map[string]User) func(*gin.Context) (*User, interface{}, error) {
	userProvider := NewMapUserProvider(users)
	return BasicAuthenticator(userProvider)
}

// BasicPayloadFunc creates a basic payload function
func BasicPayloadFunc() func(interface{}) jwt.MapClaims {
	return func(data interface{}) jwt.MapClaims {
		if v, ok := data.(map[string]interface{}); ok {
			return jwt.MapClaims{
				"user_id":  v["user_id"],
				"username": v["username"],
			}
		}
		return jwt.MapClaims{}
	}
}

// BasicIdentityHandler creates a basic identity handler
func BasicIdentityHandler() func(*gin.Context) interface{} {
	return func(c *gin.Context) interface{} {
		claims := c.MustGet("JWT_PAYLOAD").(*Claims)
		return map[string]interface{}{
			"user_id":  claims.UserID,
			"username": claims.Username,
		}
	}
}
```

#### ginauth\interfaces.go
*Language: Go | Size: 208 bytes*

```go
package ginauth

import "github.com/hsdfat/go-auth-middleware/core"

// Re-export core interfaces for backward compatibility
type TokenStorage = core.TokenStorage
type UserProvider = core.UserProvider
```

#### ginauth\jwt.go
*Language: Go | Size: 17711 bytes*

```go
package ginauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Error definitions
var (
	ErrEmptyAuthorizationHeader = errors.New("authorization header is empty")
	ErrInvalidSigningAlgorithm  = errors.New("invalid signing algorithm")
	ErrExpiredToken             = errors.New("token is expired")
	ErrMissingAuthenticatorFunc = errors.New("missing authenticator function")
	ErrForbidden                = errors.New("you don't have permission to access this resource")
)

// New creates a new authentication middleware instance
func New(config AuthConfig) *GinAuthMiddleware {
	// Set default values
	if config.Realm == "" {
		config.Realm = "gin auth"
	}
	if config.IdentityKey == "" {
		config.IdentityKey = "identity"
	}
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.TokenHeadName == "" {
		config.TokenHeadName = "Bearer"
	}
	if config.Timeout == 0 {
		config.Timeout = time.Hour
	}
	if config.MaxRefresh == 0 {
		config.MaxRefresh = time.Hour
	}
	if config.TimeFunc == nil {
		config.TimeFunc = time.Now
	}
	if config.CookieName == "" {
		config.CookieName = "jwt"
	}
	if config.CookieMaxAge == 0 {
		config.CookieMaxAge = 86400 // 24 hours
	}

	// Set default token storage if not provided
	if config.TokenStorage == nil {
		config.TokenStorage = NewInMemoryTokenStorage()
	}

	// Set default token storage configuration
	if config.TokenStorageMode == "" {
		config.TokenStorageMode = "jwt" // Default to JWT mode
	}
	if !config.EnableTokenStorage {
		config.EnableTokenStorage = true // Default to enabled
	}
	if !config.StoreTokenOnLogin {
		config.StoreTokenOnLogin = true // Default to storing tokens on login
	}
	if !config.ValidateTokenOnRequest {
		config.ValidateTokenOnRequest = true // Default to validating tokens on requests
	}

	// Set default handlers
	if config.Unauthorized == nil {
		config.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		}
	}

	if config.LoginResponse == nil {
		config.LoginResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			val, ok := c.Get("user")
			if ok {
				user := val.(*User)
				c.JSON(code, gin.H{
					"success": true,
					"code":    code,
					"token":   token,
					"expire":  expire.Format(time.RFC3339),
					"user":    user,
				})
				return
			}
			c.JSON(code, gin.H{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	if config.LogoutResponse == nil {
		config.LogoutResponse = func(c *gin.Context, code int) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": "Successfully logged out",
			})
		}
	}

	if config.RefreshResponse == nil {
		config.RefreshResponse = func(c *gin.Context, code int, token string, expire time.Time) {
			c.JSON(code, gin.H{
				"code":   code,
				"token":  token,
				"expire": expire.Format(time.RFC3339),
			})
		}
	}

	return &GinAuthMiddleware{
		Config: config,
	}
}

// NewInMemoryTokenStorage creates a new in-memory token storage
func NewInMemoryTokenStorage() *InMemoryTokenStorage {
	return core.NewInMemoryTokenStorage()
}

// MiddlewareFunc returns the Gin middleware function
func (mw *GinAuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		mw.middlewareImpl(c)
	})
}

// middlewareImpl implements the middleware logic
func (mw *GinAuthMiddleware) middlewareImpl(c *gin.Context) {
	claims, err := mw.GetClaimsFromJWT(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Check token storage if enabled and configured
	if mw.Config.EnableTokenStorage && mw.Config.ValidateTokenOnRequest && mw.Config.TokenStorage != nil {
		// Extract token from request
		tokenString := mw.extractTokenString(c)
		if tokenString != "" {
			// Generate token ID to check in storage
			tokenID := generateTokenID(map[string]interface{}{
				"user_id":  claims["user_id"],
				"username": claims["username"],
			})

			// Check if token is valid in storage
			if valid, err := mw.Config.TokenStorage.IsTokenValid(tokenID); err != nil || !valid {
				mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
				return
			}

			// Additional validation based on storage mode
			if storedToken, err := mw.Config.TokenStorage.GetToken(tokenID); err == nil {
				switch mw.Config.TokenStorageMode {
				case "bcrypt":
					// For bcrypt mode, verify the token hash
					if mw.Config.UseBcrypt {
						if !CheckPasswordHash(tokenString, storedToken) {
							mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
							return
						}
					}
				case "both":
					// For both mode, check if stored token contains the current token
					if mw.Config.UseBcrypt {
						parts := strings.Split(storedToken, ":")
						if len(parts) == 2 {
							// Check JWT part
							if parts[0] != tokenString {
								mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
								return
							}
							// Check bcrypt hash part
							if !CheckPasswordHash(tokenString, parts[1]) {
								mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(ErrExpiredToken, c))
								return
							}
						}
					}
				}
			}
		}
	}

	if mw.Config.IdentityHandler != nil {
		identity := mw.Config.IdentityHandler(c)
		c.Set(mw.Config.IdentityKey, identity)
	}

	if mw.Config.Authorizator != nil && !mw.Config.Authorizator(claims, c) {
		mw.unauthorized(c, http.StatusForbidden, mw.HTTPStatusMessageFunc(ErrForbidden, c))
		return
	}

	c.Next()
}

// GetClaimsFromJWT extracts claims from JWT token
func (mw *GinAuthMiddleware) GetClaimsFromJWT(c *gin.Context) (jwt.MapClaims, error) {
	token, err := mw.parseToken(c)
	if err != nil {
		return nil, err
	}

	if mw.Config.TimeFunc().Unix() > token.Claims.(*Claims).ExpiresAt.Unix() {
		return nil, ErrExpiredToken
	}

	claims := token.Claims.(*Claims)
	c.Set("JWT_PAYLOAD", claims)
	c.Set(mw.Config.IdentityKey, claims.UserID)

	return jwt.MapClaims{
		"user_id":  claims.UserID,
		"username": claims.Username,
		"exp":      claims.ExpiresAt.Unix(),
		"iat":      claims.IssuedAt.Unix(),
	}, nil
}

// parseToken parses the JWT token from the request
func (mw *GinAuthMiddleware) parseToken(c *gin.Context) (*jwt.Token, error) {
	var token string

	methods := strings.Split(mw.Config.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "header":
			token = mw.jwtFromHeader(c, v)
		case "query":
			token = mw.jwtFromQuery(c, v)
		case "cookie":
			token = mw.jwtFromCookie(c, v)
		}
	}

	if token == "" {
		return nil, ErrEmptyAuthorizationHeader
	}

	return jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != token.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		return []byte(mw.Config.SecretKey), nil
	})
}

// jwtFromHeader extracts JWT token from header
func (mw *GinAuthMiddleware) jwtFromHeader(c *gin.Context, key string) string {
	authHeader := c.Request.Header.Get(key)
	if authHeader == "" {
		return ""
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || !strings.EqualFold(authHeaderParts[0], mw.Config.TokenHeadName) {
		return ""
	}

	return authHeaderParts[1]
}

// jwtFromQuery extracts JWT token from query parameter
func (mw *GinAuthMiddleware) jwtFromQuery(c *gin.Context, key string) string {
	token := c.Query(key)
	if token == "" {
		return ""
	}
	return token
}

// jwtFromCookie extracts JWT token from cookie
func (mw *GinAuthMiddleware) jwtFromCookie(c *gin.Context, key string) string {
	cookie, _ := c.Cookie(key)
	return cookie
}

// extractTokenString extracts the token string from the request
func (mw *GinAuthMiddleware) extractTokenString(c *gin.Context) string {
	var token string

	methods := strings.Split(mw.Config.TokenLookup, ",")
	for _, method := range methods {
		if len(token) > 0 {
			break
		}
		parts := strings.Split(strings.TrimSpace(method), ":")
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])

		switch k {
		case "header":
			token = mw.jwtFromHeader(c, v)
		case "query":
			token = mw.jwtFromQuery(c, v)
		case "cookie":
			token = mw.jwtFromCookie(c, v)
		}
	}

	return token
}

// LoginHandler handles user login
func (mw *GinAuthMiddleware) LoginHandler(c *gin.Context) {
	if mw.Config.Authenticator == nil {
		mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(ErrMissingAuthenticatorFunc, c))
		return
	}

	user, data, err := mw.Config.Authenticator(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mw.GetClaimsFunc()(data))
	tokenString, err := token.SignedString([]byte(mw.Config.SecretKey))
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	expire := mw.Config.TimeFunc().Add(mw.Config.Timeout)

	// Store token in storage based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.StoreTokenOnLogin && mw.Config.TokenStorage != nil {
		// Generate a unique token ID
		tokenID := generateTokenID(data)

		// Determine what to store based on TokenStorageMode
		var tokenToStore string
		switch mw.Config.TokenStorageMode {
		case "jwt":
			tokenToStore = tokenString
		case "bcrypt":
			// For bcrypt mode, we could store a hash of the token
			if mw.Config.UseBcrypt {
				hashedToken, hashErr := HashPassword(tokenString)
				if hashErr != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
					return
				}
				tokenToStore = hashedToken
			} else {
				tokenToStore = tokenString
			}
		case "both":
			// Store both JWT and bcrypt hash
			if mw.Config.UseBcrypt {
				hashedToken, hashErr := HashPassword(tokenString)
				if hashErr != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
					return
				}
				tokenToStore = tokenString + ":" + hashedToken
			} else {
				tokenToStore = tokenString
			}
		default:
			tokenToStore = tokenString
		}

		err = mw.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
		if err != nil {
			mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
			return
		}
		// Store token ID in context for later use
		c.Set("token_id", tokenID)
		c.Set("token_storage_mode", mw.Config.TokenStorageMode)
		c.Set("user", user)
	}

	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			tokenString,
			mw.Config.CookieMaxAge,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.LoginResponse(c, http.StatusOK, tokenString, expire)
}

// LogoutHandler handles user logout
func (mw *GinAuthMiddleware) LogoutHandler(c *gin.Context) {
	// Handle token storage cleanup based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.TokenStorage != nil {
		// Get token ID from context if available
		if tokenID, exists := c.Get("token_id"); exists {
			if tokenIDStr, ok := tokenID.(string); ok {
				// Delete the specific token
				mw.Config.TokenStorage.DeleteToken(tokenIDStr)
			}
		}

		// Revoke all tokens for the current user if available
		if claims, exists := c.Get("JWT_PAYLOAD"); exists {
			if jwtClaims, ok := claims.(*Claims); ok {
				mw.Config.TokenStorage.RevokeAllUserTokens(jwtClaims.UserID)
			}
		}
	}

	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			"",
			-1,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.LogoutResponse(c, http.StatusOK)
}

// RefreshHandler handles token refresh
func (mw *GinAuthMiddleware) RefreshHandler(c *gin.Context) {
	tokenString, expire, err := mw.RefreshToken(c)
	if err != nil {
		mw.unauthorized(c, http.StatusUnauthorized, mw.HTTPStatusMessageFunc(err, c))
		return
	}

	// Store new token in storage based on configuration
	if mw.Config.EnableTokenStorage && mw.Config.StoreTokenOnLogin && mw.Config.TokenStorage != nil {
		// Get user data from existing claims
		if claims, exists := c.Get("JWT_PAYLOAD"); exists {
			if jwtClaims, ok := claims.(*Claims); ok {
				tokenID := generateTokenID(map[string]interface{}{
					"user_id":  jwtClaims.UserID,
					"username": jwtClaims.Username,
				})

				// Determine what to store based on TokenStorageMode
				var tokenToStore string
				switch mw.Config.TokenStorageMode {
				case "jwt":
					tokenToStore = tokenString
				case "bcrypt":
					if mw.Config.UseBcrypt {
						hashedToken, hashErr := HashPassword(tokenString)
						if hashErr != nil {
							mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
							return
						}
						tokenToStore = hashedToken
					} else {
						tokenToStore = tokenString
					}
				case "both":
					if mw.Config.UseBcrypt {
						hashedToken, hashErr := HashPassword(tokenString)
						if hashErr != nil {
							mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(hashErr, c))
							return
						}
						tokenToStore = tokenString + ":" + hashedToken
					} else {
						tokenToStore = tokenString
					}
				default:
					tokenToStore = tokenString
				}

				err = mw.Config.TokenStorage.StoreToken(tokenID, tokenToStore, expire)
				if err != nil {
					mw.unauthorized(c, http.StatusInternalServerError, mw.HTTPStatusMessageFunc(err, c))
					return
				}
				c.Set("token_id", tokenID)
				c.Set("token_storage_mode", mw.Config.TokenStorageMode)
			}
		}
	}

	if mw.Config.SendCookie {
		c.SetCookie(
			mw.Config.CookieName,
			tokenString,
			mw.Config.CookieMaxAge,
			"/",
			mw.Config.CookieDomain,
			false,
			mw.Config.CookieHTTPOnly,
		)
	}

	mw.Config.RefreshResponse(c, http.StatusOK, tokenString, expire)
}

// RefreshToken refreshes the JWT token
func (mw *GinAuthMiddleware) RefreshToken(c *gin.Context) (string, time.Time, error) {
	token, err := mw.parseToken(c)
	if err != nil {
		return "", time.Time{}, err
	}

	claims := token.Claims.(*Claims)

	origIat := claims.IssuedAt.Unix()
	if origIat < mw.Config.TimeFunc().Add(-mw.Config.MaxRefresh).Unix() {
		return "", time.Time{}, ErrExpiredToken
	}

	// Create a new token with a new expiration time
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		UserID:   claims.UserID,
		Username: claims.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(mw.Config.TimeFunc()),
			ExpiresAt: jwt.NewNumericDate(mw.Config.TimeFunc().Add(mw.Config.Timeout)),
		},
	})

	tokenString, err := newToken.SignedString([]byte(mw.Config.SecretKey))
	if err != nil {
		return "", time.Time{}, err
	}

	expire := mw.Config.TimeFunc().Add(mw.Config.Timeout)
	return tokenString, expire, nil
}

// GetClaimsFunc returns the function to extract claims from user data
func (mw *GinAuthMiddleware) GetClaimsFunc() func(interface{}) *Claims {
	return func(data interface{}) *Claims {
		claims := &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(mw.Config.TimeFunc()),
				ExpiresAt: jwt.NewNumericDate(mw.Config.TimeFunc().Add(mw.Config.Timeout)),
			},
		}

		if mw.Config.PayloadFunc != nil {
			payload := mw.Config.PayloadFunc(data)
			if userID, ok := payload["user_id"]; ok {
				claims.UserID = userID
			}
			if username, ok := payload["username"]; ok {
				claims.Username = username.(string)
			}
		}

		return claims
	}
}

// unauthorized handles unauthorized requests
func (mw *GinAuthMiddleware) unauthorized(c *gin.Context, code int, message string) {
	c.Header("WWW-Authenticate", "JWT realm="+mw.Config.Realm)
	c.Abort()
	mw.Config.Unauthorized(c, code, message)
}

// HTTPStatusMessageFunc returns HTTP status message based on error
func (mw *GinAuthMiddleware) HTTPStatusMessageFunc(err error, c *gin.Context) string {
	switch err {
	case ErrEmptyAuthorizationHeader:
		return "Authorization header is required"
	case ErrInvalidSigningAlgorithm:
		return "Invalid signing algorithm"
	case ErrExpiredToken:
		return "Token is expired"
	case ErrMissingAuthenticatorFunc:
		return "Missing authenticator function"
	case ErrForbidden:
		return "You don't have permission to access this resource"
	default:
		return err.Error()
	}
}

// generateTokenID creates a simple token ID from user data
// In production, you might want to use a proper UUID library
func generateTokenID(data interface{}) string {
	if userData, ok := data.(map[string]interface{}); ok {
		if userID, exists := userData["user_id"]; exists {
			return fmt.Sprintf("token_%v_%d", userID, time.Now().Unix())
		}
	}
	return fmt.Sprintf("token_%d", time.Now().UnixNano())
}
```

#### ginauth\structs.go
*Language: Go | Size: 2646 bytes*

```go
package ginauth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hsdfat/go-auth-middleware/core"
)

// Re-export core types for backward compatibility
type User = core.User
type MapUserProvider = core.MapUserProvider
type DatabaseUserProvider = core.DatabaseUserProvider
type InMemoryTokenStorage = core.InMemoryTokenStorage
type Claims = core.Claims

// AuthConfig holds configuration for the authentication middleware
type AuthConfig struct {
	SecretKey       string
	TokenLookup     string
	TokenHeadName   string
	Realm           string
	IdentityKey     string
	IdentityHandler func(c *gin.Context) interface{}
	Authenticator   func(c *gin.Context) (*User, interface{}, error)
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
	TokenStorage    TokenStorage
	UseBcrypt       bool
	// Token storage configuration
	EnableTokenStorage     bool   // Whether to use token storage
	TokenStorageMode       string // "jwt", "bcrypt", or "both"
	StoreTokenOnLogin      bool   // Whether to store token on login
	ValidateTokenOnRequest bool   // Whether to validate token from storage on each request
}

type GinAuthMiddleware struct {
	Config AuthConfig
}

// LoginResponse represents the response returned after a successful login.
type LoginResponse struct {
	Success     bool        `json:"success"`
	Message     string      `json:"message"`
	AccessToken string      `json:"access_token"`
	ExpiresIn   int64       `json:"expires_in"`
	User        interface{} `json:"user"` // Replace interface{} with your actual user type if needed
}

// LogoutResponse represents the response returned after a successful logout.
type LogoutResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// RefreshResponse represents the response returned after refreshing a token.
type RefreshResponse struct {
	Success     bool   `json:"success"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}
```

#### .gitignore
*Language: Text | Size: 7 bytes*

```text
*.exe
```

#### README.md
*Language: Markdown | Size: 11268 bytes*

```markdown
# Go Auth Middleware

A flexible JWT authentication middleware for Gin and Fiber frameworks with bcrypt password hashing and token storage support.

## Features

- JWT-based authentication
- Bcrypt password hashing
- Token storage interface (with in-memory implementation)
- Token refresh functionality
- Cookie support
- Flexible configuration
- Middleware for Gin and Fiber frameworks

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

## Fiber Framework Support

The middleware also supports the Fiber framework through the `fiberauth` package:

### Quick Start with Fiber

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    "github.com/hsdfat/go-auth-middleware/fiberauth"
)

func main() {
    app := fiber.New()

    // Create user provider
    users := map[string]fiberauth.User{
        "admin": {ID: 1, Username: "admin", Password: "admin123"},
        "user":  {ID: 2, Username: "user", Password: "user123"},
    }
    userProvider := fiberauth.NewMapUserProvider(users)

    // Create token storage
    tokenStorage := fiberauth.NewInMemoryTokenStorage()

    // Create auth middleware
    authMiddleware := fiberauth.NewFiberAuthMiddleware(fiberauth.AuthConfig{
        SecretKey:    "your-secret-key",
        TokenStorage: tokenStorage,
        Authenticator: authenticator(userProvider),
        Authorizator:  authorizator,
    })

    // Routes
    app.Post("/login", authMiddleware.LoginHandler())
    app.Post("/logout", authMiddleware.LogoutHandler())
    app.Post("/refresh", authMiddleware.RefreshHandler())

    // Protected routes
    protected := app.Group("/protected")
    protected.Use(authMiddleware.MiddlewareFunc())
    {
        protected.Get("/", func(c *fiber.Ctx) error {
            return c.JSON(fiber.Map{
                "message": "Protected route",
                "user_id": c.Locals("identity"),
            })
        })
    }

    app.Listen(":3000")
}
```

### Fiber Configuration

The Fiber middleware uses the same configuration structure as the Gin middleware, but with Fiber-specific context types:

```go
type AuthConfig struct {
    SecretKey       string
    TokenLookup     string
    TokenHeadName   string
    Realm           string
    IdentityKey     string
    IdentityHandler func(c *fiber.Ctx) interface{}
    Authenticator   func(c *fiber.Ctx) (interface{}, error)
    Authorizator    func(data interface{}, c *fiber.Ctx) bool
    PayloadFunc     func(data interface{}) jwt.MapClaims
    Unauthorized    func(c *fiber.Ctx, code int, message string)
    LoginResponse   func(c *fiber.Ctx, code int, token string, expire time.Time)
    LogoutResponse  func(c *fiber.Ctx, code int)
    RefreshResponse func(c *fiber.Ctx, code int, token string, expire time.Time)
    TimeFunc        func() time.Time
    Timeout         time.Duration
    MaxRefresh      time.Duration
    SendCookie      bool
    CookieName      string
    CookieMaxAge    int
    CookieDomain    string
    CookieHTTPOnly  bool
    CookieSameSite  string
    TokenStorage    TokenStorage
    UseBcrypt       bool
    // Token storage configuration
    EnableTokenStorage     bool
    TokenStorageMode       string
    StoreTokenOnLogin      bool
    ValidateTokenOnRequest bool
}
```

## Example Usage

See the `examples/` directory for complete working examples for both Gin and Fiber frameworks.

## Dependencies

- `github.com/gin-gonic/gin` - Gin web framework
- `github.com/gofiber/fiber/v2` - Fiber web framework
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `golang.org/x/crypto/bcrypt` - Password hashing

## License

MIT
```

#### go.mod
*Language: Text | Size: 1957 bytes*

```text
module github.com/hsdfat/go-auth-middleware

go 1.23.3

require (
	github.com/gin-gonic/gin v1.10.1
	github.com/golang-jwt/jwt/v5 v5.2.2
	golang.org/x/crypto v0.40.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/bytedance/sonic v1.11.6 // indirect
	github.com/bytedance/sonic/loader v0.1.1 // indirect
	github.com/cloudwego/base64x v0.1.4 // indirect
	github.com/cloudwego/iasm v0.2.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/gin-contrib/sse v0.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.20.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/gofiber/fiber/v2 v2.52.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.2 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.2.12 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/arch v0.8.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
```

#### go.sum
*Language: Text | Size: 10225 bytes*

```text
github.com/andybalholm/brotli v1.1.0 h1:eLKJA0d02Lf0mVpIDgYnqXcUn0GqVmEFny3VuID1U3M=
github.com/andybalholm/brotli v1.1.0/go.mod h1:sms7XGricyQI9K10gOSf56VKKWS4oLer58Q+mhRPtnY=
github.com/bytedance/sonic v1.11.6 h1:oUp34TzMlL+OY1OUWxHqsdkgC/Zfc85zGqw9siXjrc0=
github.com/bytedance/sonic v1.11.6/go.mod h1:LysEHSvpvDySVdC2f87zGWf6CIKJcAvqab1ZaiQtds4=
github.com/bytedance/sonic/loader v0.1.1 h1:c+e5Pt1k/cy5wMveRDyk2X4B9hF4g7an8N3zCYjJFNM=
github.com/bytedance/sonic/loader v0.1.1/go.mod h1:ncP89zfokxS5LZrJxl5z0UJcsk4M4yY2JpfqGeCtNLU=
github.com/cloudwego/base64x v0.1.4 h1:jwCgWpFanWmN8xoIUHa2rtzmkd5J2plF/dnLS6Xd/0Y=
github.com/cloudwego/base64x v0.1.4/go.mod h1:0zlkT4Wn5C6NdauXdJRhSKRlJvmclQ1hhJgA0rcu/8w=
github.com/cloudwego/iasm v0.2.0 h1:1KNIy1I1H9hNNFEEH3DVnI4UujN+1zjpuk6gwHLTssg=
github.com/cloudwego/iasm v0.2.0/go.mod h1:8rXZaNYT2n95jn+zTI1sDr+IgcD2GVs0nlbbQPiEFhY=
github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
github.com/gabriel-vasile/mimetype v1.4.3 h1:in2uUcidCuFcDKtdcBxlR0rJ1+fsokWf+uqxgUFjbI0=
github.com/gabriel-vasile/mimetype v1.4.3/go.mod h1:d8uq/6HKRL6CGdk+aubisF/M5GcPfT7nKyLpA0lbSSk=
github.com/gin-contrib/sse v0.1.0 h1:Y/yl/+YNO8GZSjAhjMsSuLt29uWRFHdHYUb5lYOV9qE=
github.com/gin-contrib/sse v0.1.0/go.mod h1:RHrZQHXnP2xjPF+u1gW/2HnVO7nvIa9PG3Gm+fLHvGI=
github.com/gin-gonic/gin v1.10.1 h1:T0ujvqyCSqRopADpgPgiTT63DUQVSfojyME59Ei63pQ=
github.com/gin-gonic/gin v1.10.1/go.mod h1:4PMNQiOhvDRa013RKVbsiNwoyezlm2rm0uX/T7kzp5Y=
github.com/go-playground/assert/v2 v2.2.0 h1:JvknZsQTYeFEAhQwI4qEt9cyV5ONwRHC+lYKSsYSR8s=
github.com/go-playground/assert/v2 v2.2.0/go.mod h1:VDjEfimB/XKnb+ZQfWdccd7VUvScMdVu0Titje2rxJ4=
github.com/go-playground/locales v0.14.1 h1:EWaQ/wswjilfKLTECiXz7Rh+3BjFhfDFKv/oXslEjJA=
github.com/go-playground/locales v0.14.1/go.mod h1:hxrqLVvrK65+Rwrd5Fc6F2O76J/NuW9t0sjnWqG1slY=
github.com/go-playground/universal-translator v0.18.1 h1:Bcnm0ZwsGyWbCzImXv+pAJnYK9S473LQFuzCbDbfSFY=
github.com/go-playground/universal-translator v0.18.1/go.mod h1:xekY+UJKNuX9WP91TpwSH2VMlDf28Uj24BCp08ZFTUY=
github.com/go-playground/validator/v10 v10.20.0 h1:K9ISHbSaI0lyB2eWMPJo+kOS/FBExVwjEviJTixqxL8=
github.com/go-playground/validator/v10 v10.20.0/go.mod h1:dbuPbCMFw/DrkbEynArYaCwl3amGuJotoKCe95atGMM=
github.com/goccy/go-json v0.10.2 h1:CrxCmQqYDkv1z7lO7Wbh2HN93uovUHgrECaO5ZrCXAU=
github.com/goccy/go-json v0.10.2/go.mod h1:6MelG93GURQebXPDq3khkgXZkazVtN9CRI+MGFi0w8I=
github.com/gofiber/fiber/v2 v2.52.8 h1:xl4jJQ0BV5EJTA2aWiKw/VddRpHrKeZLF0QPUxqn0x4=
github.com/gofiber/fiber/v2 v2.52.8/go.mod h1:YEcBbO/FB+5M1IZNBP9FO3J9281zgPAreiI1oqg8nDw=
github.com/golang-jwt/jwt/v5 v5.2.2 h1:Rl4B7itRWVtYIHFrSNd7vhTiz9UpLdi6gZhZ3wEeDy8=
github.com/golang-jwt/jwt/v5 v5.2.2/go.mod h1:pqrtFR0X4osieyHYxtmOUWsAWrfe1Q5UVIyoH402zdk=
github.com/google/go-cmp v0.5.5 h1:Khx7svrCpmxxtHBq5j2mp/xVjsi8hQMfNLvJFAlrGgU=
github.com/google/go-cmp v0.5.5/go.mod h1:v8dTdLbMG2kIc/vJvl+f65V22dbkXbowE6jgT/gNBxE=
github.com/google/gofuzz v1.0.0/go.mod h1:dBl0BpW6vV/+mYPU4Po3pmUjxk6FQPldtuIdl/M65Eg=
github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
github.com/json-iterator/go v1.1.12 h1:PV8peI4a0ysnczrg+LtxykD8LfKY9ML6u2jnxaEnrnM=
github.com/json-iterator/go v1.1.12/go.mod h1:e30LSqwooZae/UwlEbR2852Gd8hjQvJoHmT4TnhNGBo=
github.com/klauspost/compress v1.17.9 h1:6KIumPrER1LHsvBVuDa0r5xaG0Es51mhhB9BQB2qeMA=
github.com/klauspost/compress v1.17.9/go.mod h1:Di0epgTjJY877eYKx5yC51cX2A2Vl2ibi7bDH9ttBbw=
github.com/klauspost/cpuid/v2 v2.0.9/go.mod h1:FInQzS24/EEf25PyTYn52gqo7WaD8xa0213Md/qVLRg=
github.com/klauspost/cpuid/v2 v2.2.7 h1:ZWSB3igEs+d0qvnxR/ZBzXVmxkgt8DdzP6m9pfuVLDM=
github.com/klauspost/cpuid/v2 v2.2.7/go.mod h1:Lcz8mBdAVJIBVzewtcLocK12l3Y+JytZYpaMropDUws=
github.com/knz/go-libedit v1.10.1/go.mod h1:MZTVkCWyz0oBc7JOWP3wNAzd002ZbM/5hgShxwh4x8M=
github.com/leodido/go-urn v1.4.0 h1:WT9HwE9SGECu3lg4d/dIA+jxlljEa1/ffXKmRjqdmIQ=
github.com/leodido/go-urn v1.4.0/go.mod h1:bvxc+MVxLKB4z00jd1z+Dvzr47oO32F/QSNjSBOlFxI=
github.com/lib/pq v1.10.9 h1:YXG7RB+JIjhP29X+OtkiDnYaXQwpS4JEWq7dtCCRUEw=
github.com/lib/pq v1.10.9/go.mod h1:AlVN5x4E4T544tWzH6hKfbfQvm3HdbOxrmggDNAPY9o=
github.com/mattn/go-colorable v0.1.13 h1:fFA4WZxdEF4tXPZVKMLwD8oUnCTTo08duU7wxecdEvA=
github.com/mattn/go-colorable v0.1.13/go.mod h1:7S9/ev0klgBDR4GtXTXX8a3vIGJpMovkB8vQcUbaXHg=
github.com/mattn/go-isatty v0.0.16/go.mod h1:kYGgaQfpe5nmfYZH+SKPsOc2e4SrIfOl2e/yFXSvRLM=
github.com/mattn/go-isatty v0.0.20 h1:xfD0iDuEKnDkl03q4limB+vH+GxLEtL/jb4xVJSWWEY=
github.com/mattn/go-isatty v0.0.20/go.mod h1:W+V8PltTTMOvKvAeJH7IuucS94S2C6jfK/D7dTCTo3Y=
github.com/mattn/go-runewidth v0.0.16 h1:E5ScNMtiwvlvB5paMFdw9p4kSQzbXFikJ5SQO6TULQc=
github.com/mattn/go-runewidth v0.0.16/go.mod h1:Jdepj2loyihRzMpdS35Xk/zdY8IAYHsh153qUoGf23w=
github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421/go.mod h1:6dJC0mAP4ikYIbvyc7fijjWJddQyLn8Ig3JB5CqoB9Q=
github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=
github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd/go.mod h1:6dJC0mAP4ikYIbvyc7fijjWJddQyLn8Ig3JB5CqoB9Q=
github.com/modern-go/reflect2 v1.0.2 h1:xBagoLtFs94CBntxluKeaWgTMpvLxC4ur3nMaC9Gz0M=
github.com/modern-go/reflect2 v1.0.2/go.mod h1:yWuevngMOJpCy52FWWMvUC8ws7m/LJsjYzDa0/r8luk=
github.com/pelletier/go-toml/v2 v2.2.2 h1:aYUidT7k73Pcl9nb2gScu7NSrKCSHIDE89b3+6Wq+LM=
github.com/pelletier/go-toml/v2 v2.2.2/go.mod h1:1t835xjRzz80PqgE6HHgN2JOsmgYu/h4qDAS4n929Rs=
github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
github.com/rivo/uniseg v0.2.0 h1:S1pD9weZBuJdFmowNwbpi7BJ8TNftyUImj/0WQi72jY=
github.com/rivo/uniseg v0.2.0/go.mod h1:J6wj4VEh+S6ZtnVlnTBMWIodfgj8LQOQFoIToxlJtxc=
github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
github.com/stretchr/objx v0.4.0/go.mod h1:YvHI0jy2hoMjB+UWwv71VJQ9isScKT/TqJzVSSt89Yw=
github.com/stretchr/objx v0.5.0/go.mod h1:Yh+to48EsGEfYuaHDzXPcE3xhTkx73EhmCGUpEOglKo=
github.com/stretchr/objx v0.5.2/go.mod h1:FRsXN1f5AsAjCGJKqEizvkpNtU+EGNCLh3NxZ/8L+MA=
github.com/stretchr/testify v1.3.0/go.mod h1:M5WIy9Dh21IEIfnGCwXGc5bZfKNJtfHm1UVUgZn+9EI=
github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.7.1/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
github.com/stretchr/testify v1.8.0/go.mod h1:yNjHg4UonilssWZ8iaSj1OCr/vHnekPRkoO+kdMU+MU=
github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
github.com/stretchr/testify v1.8.4/go.mod h1:sz/lmYIOXD/1dqDmKjjqLyZ2RngseejIcXlSw2iwfAo=
github.com/stretchr/testify v1.9.0 h1:HtqpIVDClZ4nwg75+f6Lvsy/wHu+3BoSGCbBAcpTsTg=
github.com/stretchr/testify v1.9.0/go.mod h1:r2ic/lqez/lEtzL7wO/rwa5dbSLXVDPFyf8C91i36aY=
github.com/twitchyliquid64/golang-asm v0.15.1 h1:SU5vSMR7hnwNxj24w34ZyCi/FmDZTkS4MhqMhdFk5YI=
github.com/twitchyliquid64/golang-asm v0.15.1/go.mod h1:a1lVb/DtPvCB8fslRZhAngC2+aY1QWCk3Cedj/Gdt08=
github.com/ugorji/go/codec v1.2.12 h1:9LC83zGrHhuUA9l16C9AHXAqEV/2wBQ4nkvumAE65EE=
github.com/ugorji/go/codec v1.2.12/go.mod h1:UNopzCgEMSXjBc6AOMqYvWC1ktqTAfzJZUZgYf6w6lg=
github.com/valyala/bytebufferpool v1.0.0 h1:GqA5TC/0021Y/b9FG4Oi9Mr3q7XYx6KllzawFIhcdPw=
github.com/valyala/bytebufferpool v1.0.0/go.mod h1:6bBcMArwyJ5K/AmCkWv1jt77kVWyCJ6HpOuEn7z0Csc=
github.com/valyala/fasthttp v1.51.0 h1:8b30A5JlZ6C7AS81RsWjYMQmrZG6feChmgAolCl1SqA=
github.com/valyala/fasthttp v1.51.0/go.mod h1:oI2XroL+lI7vdXyYoQk03bXBThfFl2cVdIA3Xl7cH8g=
github.com/valyala/tcplisten v1.0.0 h1:rBHj/Xf+E1tRGZyWIWwJDiRY0zc1Js+CV5DqwacVSA8=
github.com/valyala/tcplisten v1.0.0/go.mod h1:T0xQ8SeCZGxckz9qRXTfG43PvQ/mcWh7FwZEA7Ioqkc=
golang.org/x/arch v0.0.0-20210923205945-b76863e36670/go.mod h1:5om86z9Hs0C8fWVUuoMHwpExlXzs5Tkyp9hOrfG7pp8=
golang.org/x/arch v0.8.0 h1:3wRIsP3pM4yUptoR96otTUOXI367OS0+c9eeRi9doIc=
golang.org/x/arch v0.8.0/go.mod h1:FEVrYAQjsQXMVJ1nsMoVVXPZg6p2JE2mx8psSWTDQys=
golang.org/x/crypto v0.40.0 h1:r4x+VvoG5Fm+eJcxMaY8CQM7Lb0l1lsmjGBQ6s8BfKM=
golang.org/x/crypto v0.40.0/go.mod h1:Qr1vMER5WyS2dfPHAlsOj01wgLbsyWtFn/aY+5+ZdxY=
golang.org/x/net v0.41.0 h1:vBTly1HeNPEn3wtREYfy4GZ/NECgw2Cnl+nK6Nz3uvw=
golang.org/x/net v0.41.0/go.mod h1:B/K4NNqkfmg07DQYrbwvSluqCJOOXwUjeb/5lOisjbA=
golang.org/x/sys v0.0.0-20220811171246-fbc7d0a398ab/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.5.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.6.0/go.mod h1:oPkhp1MJrh7nUepCBck5+mAzfO9JrbApNNgaTdGDITg=
golang.org/x/sys v0.34.0 h1:H5Y5sJ2L2JRdyv7ROF1he/lPdvFsd0mJHFw2ThKHxLA=
golang.org/x/sys v0.34.0/go.mod h1:BJP2sWEmIv4KK5OTEluFJCKSidICx8ciO85XgH3Ak8k=
golang.org/x/text v0.27.0 h1:4fGWRpyh641NLlecmyl4LOe6yDdfaYNrGb2zdfo4JV4=
golang.org/x/text v0.27.0/go.mod h1:1D28KMCvyooCX9hBiosv5Tz/+YLxj0j7XhWjpSUF7CU=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 h1:E7g+9GITq07hpfrRu66IVDexMakfv52eLZ2CXBWiKr4=
golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543/go.mod h1:I/5z698sn9Ka8TeJc9MKroUUfqBBauWjQqLJ2OPfmY0=
google.golang.org/protobuf v1.34.1 h1:9ddQBjfCyZPOHPUiPxpYESBLc+T8P3E+Vo4IbKZgFWg=
google.golang.org/protobuf v1.34.1/go.mod h1:c6P6GXX6sHbq/GpV6MGZEdwhWPcYBgnhAHhKbcUYpos=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405 h1:yhCVgyC4o1eVCa2tZl7eS0r+SDo693bJlVdllGtEeKM=
gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
nullprogram.com/x/optparse v1.0.0/go.mod h1:KdyPE+Igbe0jQUrVfMqDMeJQIJZEuyV7pjYmp6pbG50=
rsc.io/pdf v0.1.1/go.mod h1:n8OzWcQ6Sp37PL01nO98y4iUCRdTGarVfzxY20ICaU4=
```

