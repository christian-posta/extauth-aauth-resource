package extauthz

import (
	"testing"

	pb "aauth-service/gen/proto"
)

func TestAuthorityForSignature(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *pb.AttributeContext_HttpRequest
		want string
	}{
		{
			name: "nil request",
			req:  nil,
			want: "",
		},
		{
			name: "only GetHost no headers map",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
			},
			want: "example.com",
		},
		{
			name: "GetHost and Host equal use that",
			req: &pb.AttributeContext_HttpRequest{
				Host: "supply-chain-agent.localhost",
				Headers: map[string]string{
					"Host": "supply-chain-agent.localhost",
				},
			},
			want: "supply-chain-agent.localhost",
		},
		{
			name: "GetHost and Host equal with same non-standard port",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com:3000",
				Headers: map[string]string{
					"Host": "example.com:3000",
				},
			},
			want: "example.com:3000",
		},
		{
			name: "Host has non-standard port GetHost stripped hostname",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
				Headers: map[string]string{
					"Host": "example.com:3000",
				},
			},
			want: "example.com:3000",
		},
		{
			name: "GetHost has non-standard port Host header hostname only",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com:8443",
				Headers: map[string]string{
					"Host": "example.com",
				},
			},
			want: "example.com:8443",
		},
		{
			name: "lowercase host header key",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
				Headers: map[string]string{
					"host": "example.com:9000",
				},
			},
			want: "example.com:9000",
		},
		{
			name: "Host present prefers Host over :authority for merge",
			req: &pb.AttributeContext_HttpRequest{
				Host: "wrong",
				Headers: map[string]string{
					"Host":        "via-host:1",
					":authority": "via-authority:2",
				},
			},
			want: "via-host:1",
		},
		{
			name: "empty Host whitespace falls through to :authority then merge",
			req: &pb.AttributeContext_HttpRequest{
				Host: "fallback.test",
				Headers: map[string]string{
					"Host":        "   ",
					":authority": "fallback.test:7777",
				},
			},
			want: "fallback.test:7777",
		},
		{
			name: "no Host header merges GetHost with :authority",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
				Headers: map[string]string{
					":authority": "example.com:3000",
				},
			},
			want: "example.com:3000",
		},
		{
			name: "GetHost and :authority equal",
			req: &pb.AttributeContext_HttpRequest{
				Host: "svc.internal:8080",
				Headers: map[string]string{
					":authority": "svc.internal:8080",
				},
			},
			want: "svc.internal:8080",
		},
		{
			name: "differ only by standard 443 prefer header",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
				Headers: map[string]string{
					"Host": "example.com:443",
				},
			},
			want: "example.com:443",
		},
		{
			name: "differ only by standard 80 prefer header",
			req: &pb.AttributeContext_HttpRequest{
				Host: "example.com",
				Headers: map[string]string{
					"Host": "example.com:80",
				},
			},
			want: "example.com:80",
		},
		{
			name: "empty Host only whitespace no :authority uses GetHost",
			req: &pb.AttributeContext_HttpRequest{
				Host: "fallback.test",
				Headers: map[string]string{
					"Host": "   ",
				},
			},
			want: "fallback.test",
		},
		{
			name: "GetHost with port no Host header",
			req: &pb.AttributeContext_HttpRequest{
				Host: "full.authority:9999",
			},
			want: "full.authority:9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AuthorityForSignature(tt.req)
			if got != tt.want {
				t.Fatalf("AuthorityForSignature() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMergeGetHostAndHeader(t *testing.T) {
	t.Parallel()
	if got := mergeGetHostAndHeader("a", "a"); got != "a" {
		t.Fatalf("equal: got %q", got)
	}
	if got := mergeGetHostAndHeader("a:3000", "a"); got != "a:3000" {
		t.Fatalf("getHost has port: got %q", got)
	}
	if got := mergeGetHostAndHeader("a", "a:3000"); got != "a:3000" {
		t.Fatalf("header has port: got %q", got)
	}
	if got := mergeGetHostAndHeader("", "b:1"); got != "b:1" {
		t.Fatalf("only header: got %q", got)
	}
	if got := mergeGetHostAndHeader("c", ""); got != "c" {
		t.Fatalf("only getHost: got %q", got)
	}
}
