package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Config struct {
	Addr     string
	AllowAll bool

	// Optional TLS. If both set, we serve HTTPS.
	TLSCert string
	TLSKey  string
}

type TrustStore interface {
	SetTrusted(did string, trusted bool, reason string) error
	IsTrusted(did string) (trusted bool, reason string, ok bool)
	List() map[string]TrustEntry
}

type TrustEntry struct {
	Trusted   bool      `json:"trusted"`
	Reason    string    `json:"reason,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]TrustEntry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]TrustEntry{}}
}

func (m *MemoryStore) SetTrusted(did string, trusted bool, reason string) error {
	did = strings.TrimSpace(did)
	if did == "" {
		return errors.New("did is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[did] = TrustEntry{Trusted: trusted, Reason: reason, UpdatedAt: time.Now().UTC()}
	return nil
}

func (m *MemoryStore) IsTrusted(did string) (bool, string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[did]
	return e.Trusted, e.Reason, ok
}

func (m *MemoryStore) List() map[string]TrustEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]TrustEntry, len(m.data))
	for k, v := range m.data {
		out[k] = v
	}
	return out
}

type Server struct {
	cfg   Config
	store TrustStore
	r     http.Handler
}

func NewServer(cfg Config) *Server {
	s := &Server{
		cfg:   cfg,
		store: NewMemoryStore(),
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	// Wallet-facing endpoints:
	r.Post("/wallet/interactions/issuance", s.handleEvaluateIssuance)
	r.Post("/wallet/interactions/presentation", s.handleEvaluatePresentation)

	// Admin endpoints (simple + no auth for now; put behind nginx/basic auth).
	r.Route("/admin", func(r chi.Router) {
		r.Get("/trust", s.handleTrustList)
		r.Put("/trust/{did}", s.handleTrustPut)
		r.Delete("/trust/{did}", s.handleTrustDelete)
		r.Get("/trust/{did}", s.handleTrustGet)
	})

	s.r = r
	return s
}

func (s *Server) ListenAndServe() error {
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return http.ListenAndServeTLS(s.cfg.Addr, s.cfg.TLSCert, s.cfg.TLSKey, s.r)
	}
	return http.ListenAndServe(s.cfg.Addr, s.r)
}

func (s *Server) handleEvaluateIssuance(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, EvaluationResult{Result: "denied", Message: "invalid json"})
		return
	}

	walletDID := extractString(body, "wallet_did", "walletDID", "walletDid", "wallet")
	if s.cfg.AllowAll || walletDID == "" {
		writeJSON(w, http.StatusOK, EvaluationResult{
			Result:  "allowed",
			Data:    &EvaluationData{ClientAttestationRequested: false},
			Message: "allow-all enabled",
		})
		return
	}

	trusted, reason, ok := s.store.IsTrusted(walletDID)
	if !ok || !trusted {
		msg := "wallet not trusted"
		if ok && reason != "" {
			msg = msg + ": " + reason
		}
		writeJSON(w, http.StatusOK, EvaluationResult{
			Result:  "denied",
			Data:    &EvaluationData{ClientAttestationRequested: false},
			Message: msg,
		})
		return
	}

	writeJSON(w, http.StatusOK, EvaluationResult{
		Result: "allowed",
		Data:   &EvaluationData{ClientAttestationRequested: false},
	})
}

func (s *Server) handleEvaluatePresentation(w http.ResponseWriter, r *http.Request) {
	body, err := readJSONMap(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, EvaluationResult{Result: "denied", Message: "invalid json"})
		return
	}

	walletDID := extractString(body, "wallet_did", "walletDID", "walletDid", "wallet")
	if s.cfg.AllowAll || walletDID == "" {
		writeJSON(w, http.StatusOK, EvaluationResult{
			Result:  "allowed",
			Data:    &EvaluationData{ClientAttestationRequested: false},
			Message: "allow-all enabled",
		})
		return
	}

	trusted, reason, ok := s.store.IsTrusted(walletDID)
	if !ok || !trusted {
		msg := "wallet not trusted"
		if ok && reason != "" {
			msg = msg + ": " + reason
		}
		writeJSON(w, http.StatusOK, EvaluationResult{
			Result:  "denied",
			Data:    &EvaluationData{ClientAttestationRequested: false},
			Message: msg,
		})
		return
	}

	writeJSON(w, http.StatusOK, EvaluationResult{
		Result: "allowed",
		Data:   &EvaluationData{ClientAttestationRequested: false},
	})
}

// --- admin

func (s *Server) handleTrustList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.store.List())
}

func (s *Server) handleTrustGet(w http.ResponseWriter, r *http.Request) {
	did := chi.URLParam(r, "did")
	trusted, reason, ok := s.store.IsTrusted(did)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, TrustEntry{Trusted: trusted, Reason: reason})
}

func (s *Server) handleTrustPut(w http.ResponseWriter, r *http.Request) {
	did := chi.URLParam(r, "did")

	var req TrustUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}

	if err := s.store.SetTrusted(did, req.Trusted, req.Reason); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTrustDelete(w http.ResponseWriter, r *http.Request) {
	did := chi.URLParam(r, "did")
	_ = s.store.SetTrusted(did, false, "revoked")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- helpers

func readJSONMap(r *http.Request) (map[string]any, error) {
	defer r.Body.Close()
	var m map[string]any
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func extractString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}
