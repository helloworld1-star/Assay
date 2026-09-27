package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"strings"
)

func newTestServer() http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewServer(log).Handler()
}

// TestScanRejectsBadInput covers the paths that fail before any network call,
// so the test stays hermetic.
func TestScanRejectsBadInput(t *testing.T) {
	h := newTestServer()

	for _, tc := range []struct{ name, query string }{
		{"missing asset", "/api/v1/scan"},
		{"empty asset", "/api/v1/scan?asset="},
		{"not an asset", "/api/v1/scan?asset=hello"},
		{"bad issuer", "/api/v1/scan?asset=USDC-NOPE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Error == "" {
				t.Error("error body was empty; a caller must be able to tell why it failed")
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestUIServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The UI must present severity and accountability as separate things. If
	// someone collapses them into one score, this fails loudly.
	for _, want := range []string{"Severity — issuer capability", "Accountability — who stands behind it"} {
		if !strings.Contains(body, want) {
			t.Errorf("UI missing %q", want)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

type stubScanner struct {
	report *mechanics.Report
	err    error
}

func (s *stubScanner) ScanWithHolder(_ context.Context, _ mechanics.Asset, _ string) (*mechanics.Report, error) {
	return s.report, s.err
}

func TestScanPaths(t *testing.T) {
	const issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"

	t.Run("success", func(t *testing.T) {
		rep := &mechanics.Report{
			Asset:    mechanics.Asset{Code: "USDC", Issuer: issuer},
			Severity: mechanics.Clear,
		}
		srv := &api.Server{
			Scanner: &stubScanner{report: rep},
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got mechanics.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode report: %v", err)
		}
		if got.Asset.Code != "USDC" || got.Asset.Issuer != issuer {
			t.Errorf("Asset = %+v, want Code=USDC Issuer=%s", got.Asset, issuer)
		}
		if got.Severity != mechanics.Clear {
			t.Errorf("Severity = %v, want Clear", got.Severity)
		}
	})

	t.Run("degraded", func(t *testing.T) {
		rep := &mechanics.Report{
			Asset:    mechanics.Asset{Code: "USDC", Issuer: issuer},
			Severity: mechanics.Medium,
		}
		srv := &api.Server{
			Scanner: &stubScanner{report: rep},
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for degraded result", rec.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := &api.Server{
			Scanner: &stubScanner{err: horizon.ErrNotFound},
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})

	t.Run("upstream failure", func(t *testing.T) {
		upstreamErr := errors.New("connection refused")
		srv := &api.Server{
			Scanner: &stubScanner{err: upstreamErr},
			Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		}

		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-"+issuer, nil))

		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", rec.Code)
		}

		var body struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode error body: %v", err)
		}
		if !strings.Contains(body.Error, "connection refused") {
			t.Errorf("error body %q missing upstream error text", body.Error)
		}
	})
}
