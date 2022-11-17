package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_originMatches(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		clientOrigin       string
		relyingPartyOrigin string
		matches            bool
	}{
		{"ignore schemas", "http://www.example.com", "https://www.example.com", true},
		{"ignore ports", "http://www.example.com:8080", "https://www.example.com", true},
		{"exact", "https://www.example.com", "https://www.example.com", true},
		{"subdomain", "https://a.b.c.d.e.f.example.com", "https://example.com", true},
		{"superdomain", "https://example.com", "https://www.example.com", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.matches, originMatches(tc.clientOrigin, tc.relyingPartyOrigin))
		})
	}
}
