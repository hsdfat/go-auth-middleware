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
