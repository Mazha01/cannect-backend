// Package database provides MongoDB connectivity.
package database

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"cannect/internal/config"
)

// DB wraps the MongoDB client together with the resolved default database, so
// callers get a ready-to-use *mongo.Database without re-parsing config.
type DB struct {
	Client   *mongo.Client
	Database *mongo.Database
}

// Connect dials MongoDB using the supplied config and verifies the connection
// with a primary-read ping. The caller owns the returned client and must call
// Close on shutdown.
func Connect(ctx context.Context, cfg config.Mongo) (*DB, error) {
	opts := options.Client().
		ApplyURI(cfg.URI).
		SetConnectTimeout(cfg.ConnectTimeout).
		SetMaxPoolSize(cfg.MaxPoolSize).
		SetMinPoolSize(cfg.MinPoolSize)

	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("ping: %w", err)
	}

	return &DB{
		Client:   client,
		Database: client.Database(cfg.Database),
	}, nil
}

// Close disconnects the underlying client.
func (db *DB) Close(ctx context.Context) error {
	if db == nil || db.Client == nil {
		return nil
	}
	return db.Client.Disconnect(ctx)
}

// Ping verifies the primary is reachable; used by the /readyz probe.
func (db *DB) Ping(ctx context.Context) error {
	return db.Client.Ping(ctx, readpref.Primary())
}
