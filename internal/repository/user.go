// Package repository implements MongoDB-backed persistence for domain entities.
package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"cannect/internal/domain"
	"cannect/internal/facility/fault"
)

// UserRepository persists users in the "users" collection.
type UserRepository struct {
	col *mongo.Collection
}

// NewUserRepository binds the repository to the database's users collection.
func NewUserRepository(db *mongo.Database) *UserRepository {
	return &UserRepository{col: db.Collection("users")}
}

// EnsureIndexes creates the unique index on email. Idempotent.
func (r *UserRepository) EnsureIndexes(ctx context.Context) error {
	_, err := r.col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return fault.NewError("repo.user.EnsureIndexes", fault.Internal, err)
	}
	return nil
}

// Create inserts a new user, stamping timestamps and the generated id.
func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	const op fault.Op = "repo.user.Create"
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	now := time.Now()
	u.CreatedAt = now
	u.UpdatedAt = now

	res, err := r.col.InsertOne(ctx, u)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return fault.NewError(op, fault.AlreadyExist, err)
		}
		return fault.NewError(op, fault.Internal, err)
	}
	// InsertOne does not write the generated _id back onto the struct.
	if oid, ok := res.InsertedID.(primitive.ObjectID); ok {
		u.ID = oid
	}
	return nil
}

// GetByID returns the user by id, or a NotFound fault.
func (r *UserRepository) GetByID(ctx context.Context, id domain.ID) (*domain.User, error) {
	const op fault.Op = "repo.user.GetByID"
	var u domain.User
	err := r.col.FindOne(ctx, bson.M{"_id": id}).Decode(&u)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fault.NewError(op, fault.NotFound, err)
	}
	if err != nil {
		return nil, fault.NewError(op, fault.Internal, err)
	}
	return &u, nil
}

// GetByEmail returns the user by (lowercased) email, or a NotFound fault.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	const op fault.Op = "repo.user.GetByEmail"
	var u domain.User
	err := r.col.FindOne(ctx, bson.M{"email": strings.ToLower(strings.TrimSpace(email))}).Decode(&u)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, fault.NewError(op, fault.NotFound, err)
	}
	if err != nil {
		return nil, fault.NewError(op, fault.Internal, err)
	}
	return &u, nil
}

// Update replaces the stored user document, refreshing updatedAt.
func (r *UserRepository) Update(ctx context.Context, u *domain.User) error {
	const op fault.Op = "repo.user.Update"
	u.UpdatedAt = time.Now()
	_, err := r.col.ReplaceOne(ctx, bson.M{"_id": u.ID}, u)
	if err != nil {
		return fault.NewError(op, fault.Internal, err)
	}
	return nil
}
