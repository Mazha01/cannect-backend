package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"cannect/internal/facility/fault"
)

func TestWriteError_FaultKindMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantErrMsg string // exact for non-5xx; "" means don't assert body message
	}{
		{
			name:       "not found",
			err:        fault.NewError("repo.Get", fault.NotFound, errors.New("no rows")),
			wantStatus: http.StatusNotFound,
			wantCode:   "not_exist",
		},
		{
			name:       "bad request",
			err:        fault.NewError("svc.Create", fault.BadRequest, errors.New("empty name")),
			wantStatus: http.StatusBadRequest,
			wantCode:   "bad_request",
		},
		{
			name:       "already exist -> conflict",
			err:        fault.NewError("svc.Create", fault.AlreadyExist, errors.New("dup")),
			wantStatus: http.StatusConflict,
			wantCode:   "already_exist",
		},
		{
			name:       "unauthorized",
			err:        fault.NewError("svc.Auth", fault.Unauthorized, errors.New("bad token")),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "unauthorized",
		},
		{
			name:       "internal is masked",
			err:        fault.NewError("svc.Do", fault.Internal, errors.New("boom")),
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
		{
			name:       "plain error defaults to 500 and is masked",
			err:        errors.New("unexpected"),
			wantStatus: http.StatusInternalServerError,
			wantErrMsg: "internal server error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)

			writeError(rec, req, tc.err)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			var got ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if tc.wantCode != "" && got.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", got.Code, tc.wantCode)
			}
			if tc.wantErrMsg != "" && got.Error != tc.wantErrMsg {
				t.Errorf("error = %q, want %q", got.Error, tc.wantErrMsg)
			}
		})
	}
}

func TestWriteError_HTTPErrorWinsWithFields(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)

	he := &httpError{
		Status: http.StatusUnprocessableEntity,
		Msg:    "validation failed",
		Fields: map[string]string{"name": "required"},
	}
	writeError(rec, req, he)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	var got ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Fields["name"] != "required" {
		t.Errorf("fields = %v, want name=required", got.Fields)
	}
}

// TestFaultUnwrap guards the Unwrap fix: standard errors.Is must traverse a
// fault chain to reach a wrapped sentinel error.
func TestFaultUnwrap(t *testing.T) {
	sentinel := errors.New("sentinel")
	wrapped := fault.NewError("svc.Do", fault.Internal, sentinel)

	if !errors.Is(wrapped, sentinel) {
		t.Fatal("errors.Is could not traverse fault chain — Unwrap missing?")
	}
}
