package jwksfetch

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type MockClient struct {
	Keysets           map[string]jwk.Set
	Metadata          map[string]map[string]interface{}
	GetCalls          map[string]int
	InvalidateCalls   map[string]int
	OnInvalidate      func(uri string)
}

func NewMockClient() *MockClient {
	return &MockClient{
		Keysets:         make(map[string]jwk.Set),
		Metadata:        make(map[string]map[string]interface{}),
		GetCalls:        make(map[string]int),
		InvalidateCalls: make(map[string]int),
	}
}

func (m *MockClient) Get(ctx context.Context, uri string) (jwk.Set, error) {
	m.GetCalls[uri]++
	if set, ok := m.Keysets[uri]; ok {
		return set, nil
	}
	return nil, fmt.Errorf("mock: not found")
}

func (m *MockClient) GetMetadata(ctx context.Context, uri string) (map[string]interface{}, error) {
	if md, ok := m.Metadata[uri]; ok {
		return md, nil
	}
	return nil, fmt.Errorf("mock metadata: not found")
}

func (m *MockClient) Invalidate(uri string) {
	m.InvalidateCalls[uri]++
	if m.OnInvalidate != nil {
		m.OnInvalidate(uri)
	}
}
