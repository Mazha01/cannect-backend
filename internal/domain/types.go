package domain

import "go.mongodb.org/mongo-driver/bson/primitive"

// ID is the application-wide identifier alias. Mongo documents use ObjectID;
// aliasing keeps call sites in the domain namespace without importing the
// bson primitive package directly.
type ID = primitive.ObjectID

// ParseID parses a 24-char hex string into a domain ID, returning a typed
// error on bad input.
func ParseID(s string) (ID, error) {
	return primitive.ObjectIDFromHex(s)
}
