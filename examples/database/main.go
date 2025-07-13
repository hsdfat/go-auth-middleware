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
