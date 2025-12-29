package main

import (
	"context"
	"fmt"
	"log"

	"github.com/kainos-it-com/kainos-auth"
	"github.com/kainos-it-com/kainos-auth/store"
)

func main() {
	ctx := context.Background()

	// Initialize store (replace with your actual connection string)
	s, err := store.NewStore(ctx, "your-database-connection-string")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	// Create auth instance
	a := kainos_auth_lib.New(s,
		kainos_auth_lib.WithSecret("your-secret-key"),
		kainos_auth_lib.WithEmailVerification(true),
	)

	// Example 1: Sign up a new user (with automatic password hashing and session creation)
	signUpResponse, err := a.SignUp(ctx, kainos_auth_lib.SignUpInput{
		Name:     "John Doe",
		Email:    "john@example.com",
		Password: "securePassword123!",
	})
	if err != nil {
		log.Printf("Sign up failed: %v", err)
		return
	}
	fmt.Printf("User created: %s, Session: %s\n", signUpResponse.User.ID, signUpResponse.Session.ID)

	// Example 2: Sign in an existing user (with automatic password verification and session creation)
	signInResponse, err := a.SignIn(ctx, kainos_auth_lib.SignInInput{
		Email:    "john@example.com",
		Password: "securePassword123!",
	})
	if err != nil {
		log.Printf("Sign in failed: %v", err)
		return
	}
	fmt.Printf("User signed in: %s, Session: %s\n", signInResponse.User.ID, signInResponse.Session.ID)

	// Example 3: Create user without session (just user creation)
	userWithAccounts, err := a.CreateUser(ctx, kainos_auth_lib.SignUpInput{
		Name:     "Jane Doe",
		Email:    "jane@example.com",
		Password: "anotherSecurePassword123!",
	})
	if err != nil {
		log.Printf("User creation failed: %v", err)
		return
	}
	fmt.Printf("User created without session: %s\n", userWithAccounts.User.ID)

	// Example 4: Direct store access (your original approach still works)
	hashedPassword, err := kainos_auth_lib.HashPassword("directPassword123!")
	if err != nil {
		log.Printf("Password hashing failed: %v", err)
		return
	}

	result, err := a.Store.CreateUserWithCredential(ctx, kainos_auth_lib.CreateUserInput{
		Name:  "Direct User",
		Email: "direct@example.com",
	}, hashedPassword)
	if err != nil {
		log.Printf("Direct user creation failed: %v", err)
		return
	}
	fmt.Printf("Direct user created: %s\n", result.User.ID)
}