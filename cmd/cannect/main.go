package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cannect/internal/auth"
	"cannect/internal/config"
	"cannect/internal/database"
	"cannect/internal/email"
	"cannect/internal/logger"
	redisclient "cannect/internal/redis"
	"cannect/internal/repository"
	"cannect/internal/service"
	httpsrv "cannect/internal/transport/http"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := logger.New(cfg.Log)
	log.Info("cannect starting", "env", cfg.Env)

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bootCtx, cancelBoot := context.WithTimeout(rootCtx, 30*time.Second)
	defer cancelBoot()

	db, err := database.Connect(bootCtx, cfg.Mongo)
	if err != nil {
		return fmt.Errorf("connect mongo: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.Close(shutdownCtx); err != nil {
			log.Error("mongo disconnect", "err", err)
		}
	}()
	log.Info("connected to mongodb", "db", cfg.Mongo.Database)

	rdb, err := redisclient.New(bootCtx, cfg.Redis)
	if err != nil {
		return fmt.Errorf("connect redis: %w", err)
	}
	defer func() { _ = rdb.Close() }()
	log.Info("connected to redis", "addr", cfg.Redis.Addr)

	// Auth wiring.
	jwtMgr := auth.NewManager(cfg.Auth.JWTSecret, cfg.Auth.AccessTokenTTL)

	var mailer email.Mailer
	if smtp := email.NewSMTPMailer(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.User, cfg.SMTP.Password, cfg.SMTP.From); smtp.Enabled() {
		mailer = smtp
		log.Info("smtp mailer enabled", "host", cfg.SMTP.Host, "from", cfg.SMTP.From)
	} else {
		mailer = email.NewLogMailer(log)
		log.Info("smtp mailer disabled — using log mailer (codes printed to the log)")
	}
	userRepo := repository.NewUserRepository(db.Database)
	if err := userRepo.EnsureIndexes(bootCtx); err != nil {
		return fmt.Errorf("ensure user indexes: %w", err)
	}

	googleAuth := auth.NewGoogle(auth.GoogleConfig{
		ClientID:     cfg.Google.ClientID,
		ClientSecret: cfg.Google.ClientSecret,
		RedirectURL:  cfg.Google.RedirectURL,
	})
	if googleAuth.Enabled() {
		log.Info("google sign-in enabled (direct, like cannect-web)")
	} else {
		log.Info("google sign-in disabled (set GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET to enable)")
	}

	authSvc := service.NewAuthService(service.AuthDeps{
		Users:   userRepo,
		JWT:     jwtMgr,
		Google:  googleAuth,
		Mailer:  mailer,
		CodeTTL: cfg.Auth.VerificationCodeTTL,
	})
	authHandler := httpsrv.NewAuthHandler(authSvc, cfg.Google.PostAuthURL)

	// Admin auth — separate flow: password + Telegram OIDC second factor.
	var adminHandler *httpsrv.AdminAuthHandler
	tgOIDC := auth.NewOIDC(auth.OIDCConfig{
		Issuer:       cfg.Telegram.OIDCIssuer,
		ClientID:     cfg.Telegram.OIDCClientID,
		ClientSecret: cfg.Telegram.OIDCClientSecret,
		RedirectURL:  cfg.Telegram.OIDCRedirectURL,
		AuthURL:      cfg.Telegram.OIDCAuthURL,
		TokenURL:     cfg.Telegram.OIDCTokenURL,
		JWKSURI:      cfg.Telegram.OIDCJWKSURI,
	})
	if tgOIDC.Enabled() {
		adminSvc := service.NewAdminAuthService(service.AdminAuthDeps{
			Users: userRepo,
			JWT:   jwtMgr,
			OIDC:  tgOIDC,
			Redis: rdb,
		})
		adminHandler = httpsrv.NewAdminAuthHandler(adminSvc, cfg.Telegram.OIDCPostAuthURL)
		log.Info("admin auth enabled (password + telegram OIDC 2FA)")
	} else {
		log.Info("admin auth disabled (set TELEGRAM_OIDC_CLIENT_ID + TELEGRAM_OIDC_CLIENT_SECRET to enable)")
	}

	// HTTP.
	router := httpsrv.NewRouter(httpsrv.Deps{
		DB:       db,
		Logger:   log,
		HTTPCfg:  cfg.HTTP,
		JWT:      jwtMgr,
		Auth:     authHandler,
		Admin:    adminHandler,
		DevPages: cfg.Env != "production",
	})

	srv := &nethttp.Server{
		Addr:              ":" + cfg.HTTP.Port,
		Handler:           router,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		BaseContext:       func(_ net.Listener) context.Context { return rootCtx },
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("http: %w", err)
	case <-rootCtx.Done():
		log.Info("shutdown signal received")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("http shutdown", "err", err)
		return err
	}
	log.Info("cannect stopped cleanly")
	return nil
}
