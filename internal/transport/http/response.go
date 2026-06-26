// Package http exposes the application's HTTP API.
package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"

	"cannect/internal/facility/fault"
)

// validate is process-wide so the reflect cache survives across requests.
var validate = validator.New(validator.WithRequiredStructEnabled())

// ErrorResponse is the JSON envelope for any error.
type ErrorResponse struct {
	Error  string            `json:"error"`
	Code   string            `json:"code,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

// httpError carries a transport-level status + optional validation fields, for
// failures that happen before the service layer (bad JSON, schema validation).
// Service/domain errors use *fault.Error instead and are classified by Kind.
type httpError struct {
	Status int
	Msg    string
	Fields map[string]string
}

func (e *httpError) Error() string { return e.Msg }

func errBadRequest(msg string) *httpError { return &httpError{Status: http.StatusBadRequest, Msg: msg} }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

// decodeJSON decodes and validates a request body into v. Kept ready for the
// first endpoints; unused until handlers are added.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errBadRequest("invalid JSON: " + err.Error())
	}
	if err := validate.Struct(v); err != nil {
		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			fields := make(map[string]string, len(verrs))
			for _, fe := range verrs {
				fields[fe.Field()] = fe.Tag()
			}
			return &httpError{Status: http.StatusUnprocessableEntity, Msg: "validation failed", Fields: fields}
		}
		return errBadRequest(err.Error())
	}
	return nil
}

// statusFromKind maps a fault.Kind onto an HTTP status code. Mirrors the
// classification used across the service layer.
func statusFromKind(k fault.Kind) int {
	switch k {
	case fault.Permission, fault.Unauthorized:
		return http.StatusUnauthorized
	case fault.NotFound:
		return http.StatusNotFound
	case fault.AlreadyExist:
		return http.StatusConflict
	case fault.BadRequest:
		return http.StatusBadRequest
	case fault.Forbidden:
		return http.StatusForbidden
	case fault.RateLimited:
		return http.StatusTooManyRequests
	case fault.Internal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// writeError maps transport + fault errors onto HTTP responses. Transport-level
// httpError wins (it carries validation fields); everything else is treated as
// a *fault.Error and classified by Kind, defaulting to 500 for unclassified
// errors.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.Status, ErrorResponse{Error: he.Msg, Fields: he.Fields})
		return
	}

	var f *fault.Error
	if !errors.As(err, &f) {
		f = fault.NewError("http.writeError", fault.Internal, err)
	}

	status := statusFromKind(f.Kind)
	resp := ErrorResponse{Code: f.Kind.String()}
	if status >= http.StatusInternalServerError {
		// Don't leak internals to clients; log the full chain server-side.
		slog.Default().ErrorContext(r.Context(), "internal error",
			"err", err, "op", string(f.Op), "path", r.URL.Path)
		resp.Error = "internal server error"
	} else {
		resp.Error = f.Error()
	}
	writeJSON(w, status, resp)
}

// clientIP extracts the best-effort client IP for audit logs.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
