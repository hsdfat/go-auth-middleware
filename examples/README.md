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