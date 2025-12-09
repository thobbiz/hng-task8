package main

import (
	"context"
	"database/sql"
	apikey "hng-stage8/api-key"
	"hng-stage8/auth"
	"hng-stage8/definitions"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"

	"github.com/joho/godotenv"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	_ "hng-stage8/docs"
)

func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, relying on system env vars")
	}

	definitions.PaystackSecretKey = os.Getenv("PAYSTACK_SECRET_KEY")
	if definitions.PaystackSecretKey == "" {
		log.Fatal("PAYSTACK_SECRET_KEY is missing")
	}

	definitions.GoogleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "http://localhost" + os.Getenv("SERVER_ADDRESS") + "/auth/google/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	var err error
	dbConnectionString := os.Getenv("DB_CONNECTION_STRING")
	if dbConnectionString == "" {
		log.Fatal("DB_CONNECTION_STRING is missing")
	}

	definitions.DB, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		log.Fatalf("Error opening database connection: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = definitions.DB.PingContext(ctx); err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	log.Println("Successfully connected to MySQL")
}

// @title           Google auth $ Paystack Payment API
// @version         1.0
// @description     A sample API for handling Paystack payments in Go. It also provides Google authentication. Users can authenticate with Google and use the API to initiate payments.
// @termsOfService  http://swagger.io/terms/

// @contact.name    API Support
// @contact.url     http://www.swagger.io/support
// @contact.email   support@swagger.io

// @license.name    Apache 2.0
// @license.url     http://www.apache.org/licenses/LICENSE-2.0.html

// @host            localhost:8080
// @BasePath        /
func main() {
	defer definitions.DB.Close()

	router := gin.Default()

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("/auth/google", auth.GoogleLoginHandler)
	router.GET("/auth/google/callback", auth.GoogleCallbackHandler)

	apiRoute := router.Group("/keys")
	apiRoute.Use(auth.AuthMiddleware()) // <--- THIS LINE IS CRITICAL
	{
		apiRoute.POST("/create", apikey.CreateApiKeyHandler)
	}

	// protected := router.Group("/payments")
	// protected.Use(AuthMiddleware())
	// {
	// 	protected.POST("/paystack/initiate", initiatePayment)
	// 	protected.GET("/:reference/status", checkStatus)
	// }

	serverAddr := os.Getenv("SERVER_ADDRESS")
	if serverAddr == "" {
		serverAddr = ":8080"
	}

	log.Printf("Starting Gin server on http://localhost%s", serverAddr)
	if err := router.Run(serverAddr); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}
