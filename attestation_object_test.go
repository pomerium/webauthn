package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalAttestationObject(t *testing.T) {
	readAttestationObject := func(name string) []byte {
		raw, err := os.ReadFile("testdata/attestation" + name + "Response.json")
		require.NoError(t, err)
		var obj struct {
			Response struct {
				AttestationObject string `json:"attestationObject"`
			} `json:"response"`
		}
		err = json.Unmarshal(raw, &obj)
		require.NoError(t, err)

		raw, err = base64.RawURLEncoding.DecodeString(obj.Response.AttestationObject)
		require.NoError(t, err)

		return raw
	}
	mapKeys := func(m map[string]interface{}) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}

	t.Run("android key", func(t *testing.T) {
		raw := readAttestationObject("AndroidKey")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "android-key", attestationObject.Format)
		assert.Equal(t, []string{"alg", "sig", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("apple", func(t *testing.T) {
		raw := readAttestationObject("Apple")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "apple", attestationObject.Format)
		assert.Equal(t, []string{"alg", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("at key", func(t *testing.T) {
		raw := readAttestationObject("ATKey")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "packed", attestationObject.Format)
		assert.Equal(t, []string{"alg", "sig", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("none", func(t *testing.T) {
		raw := readAttestationObject("None")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "none", attestationObject.Format)
		assert.Equal(t, []string(nil), mapKeys(attestationObject.Statement))
	})
	t.Run("packed", func(t *testing.T) {
		raw := readAttestationObject("Packed")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "packed", attestationObject.Format)
		assert.Equal(t, []string{"alg", "sig", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("packed 512", func(t *testing.T) {
		raw := readAttestationObject("Packed512")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "packed", attestationObject.Format)
		assert.Equal(t, []string{"alg", "sig"}, mapKeys(attestationObject.Statement))
	})
	t.Run("tpm sha1", func(t *testing.T) {
		raw := readAttestationObject("TPMSHA1")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "tpm", attestationObject.Format)
		assert.Equal(t, []string{"alg", "certInfo", "pubArea", "sig", "ver", "x5c"}, mapKeys(attestationObject.Statement))

	})
	t.Run("tpm sha256", func(t *testing.T) {
		raw := readAttestationObject("TPMSHA256")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "tpm", attestationObject.Format)
		assert.Equal(t, []string{"alg", "certInfo", "pubArea", "sig", "ver", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("trust key t110", func(t *testing.T) {
		raw := readAttestationObject("TrustKeyT110")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "packed", attestationObject.Format)
		assert.Equal(t, []string{"alg", "sig", "x5c"}, mapKeys(attestationObject.Statement))
	})
	t.Run("u2f", func(t *testing.T) {
		raw := readAttestationObject("U2F")
		attestationObject, remaining, err := UnmarshalAttestationObject(raw)
		assert.NoError(t, err)
		assert.Empty(t, remaining)
		assert.NotEmpty(t, attestationObject.AuthData)
		assert.Equal(t, "fido-u2f", attestationObject.Format)
		assert.Equal(t, []string{"sig", "x5c"}, mapKeys(attestationObject.Statement))
	})
}
