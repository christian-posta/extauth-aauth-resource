package pending

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound       = errors.New("pending entry not found")
	ErrInvalidState   = errors.New("pending entry in wrong state for this transition")
	ErrCodeConsumed   = errors.New("interaction code already used")
	ErrExpired        = errors.New("pending entry expired")
)

// MemoryStore is a thread-safe in-memory pending Store with TTL eviction.
type MemoryStore struct {
	mu      sync.RWMutex
	byID    map[string]*Entry
	byCode  map[string]string // code → id
	ttl     time.Duration
}

// NewMemoryStore creates a MemoryStore that evicts entries after ttl.
// A janitor goroutine runs every janitorInterval.
func NewMemoryStore(ttl, janitorInterval time.Duration) *MemoryStore {
	s := &MemoryStore{
		byID:   make(map[string]*Entry),
		byCode: make(map[string]string),
		ttl:    ttl,
	}
	go s.janitor(janitorInterval)
	return s
}

func (s *MemoryStore) Create(e *Entry) error {
	if e.ID == "" {
		e.ID = generateID()
	}
	if e.Code == "" {
		return fmt.Errorf("pending entry must have a Code")
	}
	if e.OAuthState == "" {
		e.OAuthState = generateID()
	}
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.ExpiresAt.IsZero() {
		e.ExpiresAt = now.Add(s.ttl)
	}
	if e.State == "" {
		e.State = StatePending
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[e.ID]; exists {
		return fmt.Errorf("duplicate pending ID %s", e.ID)
	}
	if _, exists := s.byCode[e.Code]; exists {
		return fmt.Errorf("duplicate interaction code %s", e.Code)
	}
	clone := *e
	s.byID[e.ID] = &clone
	s.byCode[e.Code] = e.ID
	return nil
}

func (s *MemoryStore) ByID(id string) (*Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	if (e.State == StatePending || e.State == StateInteracting) && time.Now().After(e.ExpiresAt) {
		return nil, false
	}
	clone := *e
	return &clone, true
}

func (s *MemoryStore) ByCode(code string) (*Entry, bool) {
	s.mu.RLock()
	id, ok := s.byCode[code]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return s.ByID(id)
}

func (s *MemoryStore) MarkInteracting(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if e.State != StatePending {
		return ErrInvalidState
	}
	e.State = StateInteracting
	return nil
}

func (s *MemoryStore) Complete(id, opaqueToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if e.State != StateInteracting && e.State != StatePending {
		return ErrInvalidState
	}
	e.State = StateComplete
	e.OpaqueToken = opaqueToken
	return nil
}

func (s *MemoryStore) Fail(id, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	e.State = StateFailed
	e.LastErr = errMsg
	return nil
}

func (s *MemoryStore) Consume(id string) (*Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if e.State != StateComplete {
		return nil, ErrInvalidState
	}
	e.State = StateConsumed
	clone := *e
	return &clone, nil
}

func (s *MemoryStore) janitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.evictExpired()
	}
}

func (s *MemoryStore) evictExpired() {
	now := time.Now()
	// Keep consumed/failed entries for a short grace period for debugging,
	// but remove them after 2× TTL.
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.byID {
		remove := false
		switch e.State {
		case StatePending, StateInteracting:
			remove = now.After(e.ExpiresAt)
		case StateComplete, StateFailed, StateConsumed:
			remove = now.After(e.ExpiresAt.Add(e.ExpiresAt.Sub(e.CreatedAt)))
		}
		if remove {
			delete(s.byID, id)
			delete(s.byCode, e.Code)
		}
	}
}

// ByOAuthState looks up an entry by its OAuth state token.
func (s *MemoryStore) ByOAuthState(state string) *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.byID {
		if e.OAuthState == state {
			clone := *e
			return &clone
		}
	}
	return nil
}

// GenerateID creates a random hex ID suitable for pending entry IDs.
func GenerateID() string {
	return generateID()
}

// GenerateCode creates a random 8-character uppercase alphanumeric interaction code.
func GenerateCode() string {
	b := make([]byte, 4)
	rand.Read(b) //nolint:errcheck
	code := strings.ToUpper(hex.EncodeToString(b))
	return code[:8]
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
