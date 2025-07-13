package fiberauth

import "github.com/hsdfat/go-auth-middleware/core"

// Re-export core bcrypt functions for backward compatibility
var (
	HashPassword      = core.HashPassword
	CheckPasswordHash = core.CheckPasswordHash
	HashToken         = core.HashToken
	CheckTokenHash    = core.CheckTokenHash
)
