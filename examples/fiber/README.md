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