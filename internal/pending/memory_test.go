package pending_test

import (
	"testing"
	"time"

	"aauth-service/internal/pending"
)

func newStore() *pending.MemoryStore {
	return pending.NewMemoryStore(15*time.Minute, time.Hour)
}

func newEntry(resourceID, agentID, agentJKT string) *pending.Entry {
	return &pending.Entry{
		Code:       pending.GenerateCode(),
		ResourceID: resourceID,
		AgentID:    agentID,
		AgentJKT:   agentJKT,
		Scope:      "read:user",
	}
}

func TestCreateAndByID(t *testing.T) {
	s := newStore()
	e := newEntry("res1", "agent1", "jkt1")
	if err := s.Create(e); err != nil {
		t.Fatal(err)
	}
	got, ok := s.ByID(e.ID)
	if !ok {
		t.Fatal("expected to find entry by ID")
	}
	if got.State != pending.StatePending {
		t.Fatalf("expected pending state, got %s", got.State)
	}
}

func TestByCode(t *testing.T) {
	s := newStore()
	e := newEntry("res1", "agent1", "jkt1")
	s.Create(e)

	got, ok := s.ByCode(e.Code)
	if !ok {
		t.Fatal("expected to find entry by code")
	}
	if got.ID != e.ID {
		t.Fatalf("ID mismatch: %s != %s", got.ID, e.ID)
	}
}

func TestStateTransitions(t *testing.T) {
	s := newStore()
	e := newEntry("res1", "agent1", "jkt1")
	s.Create(e)

	if err := s.MarkInteracting(e.ID); err != nil {
		t.Fatalf("MarkInteracting: %v", err)
	}
	got, _ := s.ByID(e.ID)
	if got.State != pending.StateInteracting {
		t.Fatalf("expected interacting, got %s", got.State)
	}

	if err := s.Complete(e.ID, "opaque-token-value"); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	got, _ = s.ByID(e.ID)
	if got.State != pending.StateComplete {
		t.Fatalf("expected complete, got %s", got.State)
	}
	if got.OpaqueToken != "opaque-token-value" {
		t.Fatalf("OpaqueToken not set")
	}

	consumed, err := s.Consume(e.ID)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if consumed.OpaqueToken != "opaque-token-value" {
		t.Fatalf("Consume: OpaqueToken not returned")
	}
	got, _ = s.ByID(e.ID)
	if got.State != pending.StateConsumed {
		t.Fatalf("expected consumed, got %s", got.State)
	}
}

func TestInvalidTransitions(t *testing.T) {
	s := newStore()
	e := newEntry("res1", "agent1", "jkt1")
	s.Create(e)

	// cannot Complete from pending (must go through interacting first is optional, but Complete does accept pending state)
	// actually Complete accepts both pending and interacting — try invalid: consume from pending
	if _, err := s.Consume(e.ID); err == nil {
		t.Fatal("expected error consuming from pending state")
	}
}

func TestDuplicateCode(t *testing.T) {
	s := newStore()
	e1 := newEntry("res1", "agent1", "jkt1")
	s.Create(e1)

	e2 := &pending.Entry{Code: e1.Code, ResourceID: "res1", AgentID: "agent2", AgentJKT: "jkt2"}
	if err := s.Create(e2); err == nil {
		t.Fatal("expected error on duplicate code")
	}
}

func TestFail(t *testing.T) {
	s := newStore()
	e := newEntry("res1", "agent1", "jkt1")
	s.Create(e)
	s.MarkInteracting(e.ID)
	s.Fail(e.ID, "oauth error")

	got, ok := s.ByID(e.ID)
	if !ok {
		t.Fatal("entry should still be retrievable after fail")
	}
	if got.State != pending.StateFailed {
		t.Fatalf("expected failed, got %s", got.State)
	}
	if got.LastErr != "oauth error" {
		t.Fatalf("LastErr not set: %q", got.LastErr)
	}
}
