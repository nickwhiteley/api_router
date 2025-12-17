package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"api-translation-platform/internal/container"
	"api-translation-platform/internal/repositories"
	"api-translation-platform/internal/services"

	"go.uber.org/fx"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run cmd/admin-token/main.go <username>")
		fmt.Println("Example: go run cmd/admin-token/main.go admin")
		os.Exit(1)
	}

	username := os.Args[1]

	app := fx.New(
		container.Module,
		fx.Invoke(func(
			authService services.AuthenticationService,
			userRepo repositories.UserRepository,
		) {
			ctx := context.Background()

			// Get user by username
			user, err := userRepo.GetByUsername(ctx, username)
			if err != nil {
				log.Fatalf("Failed to find user '%s': %v", username, err)
			}

			// Generate JWT token
			token, err := authService.GenerateJWT(ctx, user)
			if err != nil {
				log.Fatalf("Failed to generate JWT token: %v", err)
			}

			fmt.Printf("JWT Token for user '%s':\n", username)
			fmt.Printf("%s\n", token)
			fmt.Printf("\nUse this token in the Authorization header:\n")
			fmt.Printf("Authorization: Bearer %s\n", token)
			fmt.Printf("\nExample curl command:\n")
			fmt.Printf("curl -H \"Authorization: Bearer %s\" http://localhost:8080/api/v1/organisations\n", token)
		}),
	)

	if err := app.Start(context.Background()); err != nil {
		log.Fatalf("Failed to start application: %v", err)
	}

	app.Stop(context.Background())
}
