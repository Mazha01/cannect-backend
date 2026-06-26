// Command seed creates or updates an admin account so the admin auth flow can
// be exercised (e.g. from Postman). Usage:
//
//	go run ./cmd/seed --email admin@cannect.kz --password 'Passw0rd!'
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"cannect/internal/auth"
	"cannect/internal/config"
	"cannect/internal/database"
	"cannect/internal/domain"
	"cannect/internal/facility/fault"
	"cannect/internal/repository"
)

func main() {
	email := flag.String("email", "", "admin email (required)")
	password := flag.String("password", "", "admin password (required)")
	role := flag.String("role", "admin", "role: admin | moderator | user")
	flag.Parse()

	if *email == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "usage: seed --email <email> --password <password> [--role admin]")
		os.Exit(2)
	}

	if err := run(*email, *password, *role); err != nil {
		fmt.Fprintf(os.Stderr, "seed failed: %v\n", err)
		os.Exit(1)
	}
}

func run(email, password, role string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := database.Connect(ctx, cfg.Mongo)
	if err != nil {
		return fmt.Errorf("connect mongo: %w", err)
	}
	defer func() { _ = db.Close(context.Background()) }()

	repo := repository.NewUserRepository(db.Database)
	if err := repo.EnsureIndexes(ctx); err != nil {
		return err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	existing, err := repo.GetByEmail(ctx, email)
	switch {
	case err == nil:
		existing.PasswordHash = hash
		existing.Role = domain.UserRole(role)
		existing.AuthProvider = domain.AuthProviderEmail
		existing.EmailVerified = true
		if err := repo.Update(ctx, existing); err != nil {
			return err
		}
		fmt.Printf("updated %s (role=%s, id=%s)\n", existing.Email, existing.Role, existing.ID.Hex())
		return nil
	case fault.Is(fault.NotFound, err):
		user := &domain.User{
			Email:         email,
			PasswordHash:  hash,
			AuthProvider:  domain.AuthProviderEmail,
			Role:          domain.UserRole(role),
			EmailVerified: true,
		}
		if err := repo.Create(ctx, user); err != nil {
			return err
		}
		fmt.Printf("created %s (role=%s, id=%s)\n", user.Email, user.Role, user.ID.Hex())
		return nil
	default:
		return err
	}
}
