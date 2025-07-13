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
