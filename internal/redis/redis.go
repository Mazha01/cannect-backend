// Package redis builds the application-wide Redis client.
package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"cannect/internal/config"
)

// New connects to Redis and verifies the connection with PING.
func New(ctx context.Context, cfg config.Redis) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return client, nil
}
