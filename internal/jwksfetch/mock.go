package jwksfetch

import (
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type MockClient struct {
	Keysets map[string]jwk.Set
}

func NewMockClient() *MockClient {
	return &MockClient{
		Keysets: make(map[string]jwk.Set),
	}
}

func (m *MockClient) Get(ctx context.Context, uri string) (jwk.Set, error) {
	if set, ok := m.Keysets[uri]; ok {
		return set, nil
	}
	return nil, fmt.Errorf("mock: not found")
}

func (m *MockClient) Invalidate(uri string) {}
