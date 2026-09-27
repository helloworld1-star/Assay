// Package api serves the Assay HTTP interface and the single-file UI.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

//go:embed ui/index.html
var uiFS embed.FS

// Scanner describes what the API server needs from a scanner.
type Scanner interface {
	ScanWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Report, error)
}

// Server serves scan results.
type Server struct {
	Scanner Scanner
	Log     *slog.Logger
}

// NewServer returns a Server backed by the production scanner.
func NewServer(log *slog.Logger) *Server {
	return &Server{Scanner: scan.New(), Log: log}
}

// Handler returns the configured HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/scan", s.handleScan)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /", s.handleUI)
	return mux
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

type errorBody struct {
	Error string `json:"error"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("asset")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, errorBody{"missing ?asset=CODE-ISSUER"})
		return
	}

	asset, err := scan.ParseAsset(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}

	holder := r.URL.Query().Get("holder")
	if holder != "" {
		if err := scan.ValidateHolder(holder); err != nil {
			writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	report, err := s.Scanner.ScanWithHolder(ctx, asset, holder)
	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, errorBody{"asset not found on the ledger"})
			return
		}
		s.Log.Error("scan failed", "asset", asset.String(), "err", err)
		// The upstream error is returned rather than a generic message: a user
		// deciding whether to trust an asset needs to know the difference
		// between "safe" and "we could not check".
		writeJSON(w, http.StatusBadGateway, errorBody{"scan failed: " + err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, report)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
