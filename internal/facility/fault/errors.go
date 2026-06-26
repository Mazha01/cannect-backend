package fault

import (
	"bytes"
	"fmt"
)

// Error is the type that implements the fault interface.
// It contains a number of fields, each of different type.
// An Error value may leave some values unset.
type Error struct {
	// Op is the operation being performed, usually the name of the method
	// being invoked (GetSpace, Put, etc.). It should not contain an at sign @.
	Op Op
	// Kind is the class of fault, such as permission failure,
	// or "Other" if its class is unknown or irrelevant.
	Kind Kind
	// The underlying fault that triggered this one, if any.
	Err error
}

func (e *Error) isZero() bool {
	return e.Op == "" && e.Kind == "" && e.Err == nil
}

// Unwrap exposes the wrapped error so the standard errors.Is / errors.As can
// traverse a fault chain. Without it, a *Error terminates the chain and hides
// any sentinel or typed error it wraps.
func (e *Error) Unwrap() error {
	return e.Err
}

// Op describes an operation, usually as the package and method,
// such as "key/server.Lookup".
type Op string

// Separator is the string used to separate nested errors. By
// default, to make errors easier on the eye, nested errors are
// indented on a new line. A server may instead choose to keep each
// fault on a single line by modifying the separator string, perhaps
// to ":: ".
var Separator = ":\n\t"

// Kind defines the kind of fault this is, mostly for use by systems
// such as FUSE that must act differently depending on the fault.
type Kind string

// Kinds of errors.
//
// The values of the fault kinds are common between both
// clients and servers. Do not reorder this list or remove
// any items since that will change their values.
// New items must be added only to the end.
const (
	Other        Kind = "other"      // Unclassified fault. This value is not printed in the fault message.
	Permission   Kind = "permission" // Permission denied.
	Unauthorized Kind = "unauthorized"
	BadRequest   Kind = "bad_request"   // Invalid request data
	AlreadyExist Kind = "already_exist" // Item already exists.
	NotFound     Kind = "not_exist"     // Item does not exist.
	Internal     Kind = "internal"      // Internal fault or inconsistency.
	// Appended (per the note above, new kinds go at the end).
	Forbidden   Kind = "forbidden"    // Authenticated but not allowed / precondition unmet.
	RateLimited Kind = "rate_limited" // Too many requests; retry later.
)

func (k Kind) String() string {
	return string(k)
}

// NewError builds an fault value from its arguments.
func NewError(op Op, kind Kind, err error) *Error {
	return &Error{
		Op:   op,
		Kind: kind,
		Err:  err,
	}
}

// NewStringError builds an fault value from its arguments.
func NewStringError(op Op, kind Kind, errString string) error {
	return &Error{
		Op:   op,
		Kind: kind,
		Err:  Str(errString),
	}
}

// Wrap is helper function, which should use for own ErrorType to store wrap stack.
func Wrap(op Op, err error) *Error {
	e := &Error{
		Op:   op,
		Kind: Other,
		Err:  err,
	}

	prev, ok := err.(*Error)
	if ok {
		e.Kind = prev.Kind
		prev.Kind = Other
	}

	return e
}

// pad appends str to the buffer if the buffer already has some data.
func pad(b *bytes.Buffer, str string) {
	if b.Len() == 0 {
		return
	}
	b.WriteString(str)
}

func (e *Error) Error() string {
	b := new(bytes.Buffer)
	if e.Op != "" {
		pad(b, ": ")
		b.WriteString(string(e.Op))
	}
	if e.Kind != "" {
		pad(b, ": ")
		b.WriteString(e.Kind.String())
	}
	if e.Err != nil {
		// Indent on new line if we are cascading non-empty Upspin errors.
		if prevErr, ok := e.Err.(*Error); ok {
			if !prevErr.isZero() {
				pad(b, ": ")
				b.WriteString(e.Err.Error())
			}
		} else {
			pad(b, ": ")
			b.WriteString(e.Err.Error())
		}
	}
	if b.Len() == 0 {
		return "no fault"
	}
	return b.String()
}

// Recreate the errors.New functionality of the standard Go errors package
// so we can create simple text errors when needed.

// Str returns an fault that formats as the given text. It is intended to
// be used as the fault-typed argument to the E function.
func Str(text string) error {
	return &errorString{text}
}

// errorString is a trivial implementation of fault.
type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

// Errorf is equivalent to fmt.Errorf, but allows clients to import only this
// package for all fault handling.
func Errorf(format string, args ...interface{}) error {
	return &errorString{fmt.Sprintf(format, args...)}
}

// Match compares its two fault arguments. It can be used to check
// for expected errors in tests. Both arguments must have underlying
// type *Error or Match will return false. Otherwise it returns true
// if every non-zero element of the first fault is equal to the
// corresponding element of the second.
// If the Err field is a *Error, Match recurs on that field;
// otherwise it compares the strings returned by the Error methods.
// Elements that are in the second argument but not present in
// the first are ignored.
//
// For example,
//
//	Match(errors.E(upspin.UserName("joe@schmoe.com"), errors.Permission), err)
//
// tests whether err is an Error with Kind=Permission and User=joe@schmoe.com.
func Match(err1, err2 error) bool {
	e1, ok := err1.(*Error)
	if !ok {
		return false
	}
	e2, ok := err2.(*Error)
	if !ok {
		return false
	}
	if e1.Op != "" && e2.Op != e1.Op {
		return false
	}
	if e1.Kind != Other && e2.Kind != e1.Kind {
		return false
	}
	if e1.Err != nil {
		if _, ok := e1.Err.(*Error); ok {
			return Match(e1.Err, e2.Err)
		}
		if e2.Err == nil || e2.Err.Error() != e1.Err.Error() {
			return false
		}
	}
	return true
}

// Is reports whether err is an *Error of the given Kind.
// If err is nil then Is returns false.
func Is(kind Kind, err error) bool {
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	if e.Kind != Other {
		return e.Kind == kind
	}
	if e.Err != nil {
		return Is(kind, e.Err)
	}
	return false
}
