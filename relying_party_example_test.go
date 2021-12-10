package webauthn_test

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pomerium/webauthn"
)

func ExampleRelyingParty_VerifyAuthenticationCeremony() {
	ctx := context.Background()

	origin := "http://localhost:5000"
	storage := webauthn.NewInMemoryCredentialStorage()
	relyingParty := webauthn.NewRelyingParty(origin, storage)

	// authentication assumes an existing public key, so set it
	_ = storage.SetCredential(context.Background(), &webauthn.Credential{
		ID: []byte{
			0xed, 0xc5, 0x97, 0xe5, 0x51, 0xb5, 0x1f, 0xb2,
			0x60, 0x04, 0x05, 0x6d, 0xc5, 0xfd, 0xef, 0x69,
			0x4d, 0xd1, 0xc6, 0xfc, 0xa4, 0xb5, 0x2c, 0x84,
			0xa4, 0xbc, 0x5c, 0x0a, 0xae, 0x8b, 0x6a, 0xa5,
			0x98, 0xdd, 0x65, 0x75, 0x61, 0x67, 0x0a, 0xbd,
			0xa8, 0xc3, 0xec, 0xa1, 0xda, 0x1d, 0xd1, 0x28,
			0xa4, 0xd4, 0x22, 0x6d, 0xb0, 0x9b, 0xbd, 0x3a,
			0x41, 0xaa, 0xd1, 0xd7, 0x49, 0x94, 0x67, 0xaa,
		},
		PublicKey: []byte{
			0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21,
			0x58, 0x20, 0x93, 0x9f, 0x98, 0xa3, 0xdd, 0x89,
			0x22, 0xfb, 0xa0, 0xa8, 0x2c, 0xbd, 0xf7, 0xf7,
			0xa3, 0x8b, 0x57, 0xd9, 0x58, 0xf8, 0xc3, 0xa4,
			0xed, 0xc6, 0x64, 0xf7, 0x46, 0x3b, 0xcf, 0xe3,
			0x45, 0x64, 0x22, 0x58, 0x20, 0x31, 0xa3, 0xaf,
			0xa1, 0xda, 0x87, 0x5a, 0x08, 0x4b, 0xd0, 0x3a,
			0xcf, 0x33, 0x3e, 0xf8, 0x40, 0x81, 0x1a, 0x2f,
			0xe4, 0xa1, 0x0b, 0x4a, 0x4b, 0x51, 0xa9, 0xc0,
			0xcb, 0xaf, 0x4b, 0x84, 0xfb,
		},
	})

	var options webauthn.PublicKeyCredentialRequestOptions
	_ = json.Unmarshal([]byte(`
		{
		  "allowCredentials": [
			{
			  "type": "public-key",
			  "id": "7cWX5VG1H7JgBAVtxf3vaU3RxvyktSyEpLxcCq6LaqWY3WV1YWcKvajD7KHaHdEopNQibbCbvTpBqtHXSZRnqg"
			}
		  ],
		  "challenge": "dGVzdC1jaGFsbGVuZ2U",
		  "timeout": 15000
		}
	`), &options)
	var response webauthn.PublicKeyAssertionCredential
	_ = json.Unmarshal([]byte(`
		{
		  "id": "7cWX5VG1H7JgBAVtxf3vaU3RxvyktSyEpLxcCq6LaqWY3WV1YWcKvajD7KHaHdEopNQibbCbvTpBqtHXSZRnqg",
		  "type": "public-key",
		  "rawId": "7cWX5VG1H7JgBAVtxf3vaU3RxvyktSyEpLxcCq6LaqWY3WV1YWcKvajD7KHaHdEopNQibbCbvTpBqtHXSZRnqg",
		  "response": {
			"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
			"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ",
			"signature": "MEYCIQCqBbzRvp3ZmvseoMnrevFt0HNhvIh0idFdjREw7kmv_AIhAPFPTNL0lnAsgCmemU4BReqSBPYKAw5uEKfmYI4rp9Lf"
		  }
		}
	`), &response)

	credential, err := relyingParty.VerifyAuthenticationCeremony(ctx, &options, &response)
	if err != nil {
		panic(err)
	}

	bs, _ := json.Marshal(credential)
	fmt.Println(string(bs))
	// Output: {"id":"7cWX5VG1H7JgBAVtxf3vaU3RxvyktSyEpLxcCq6LaqWY3WV1YWcKvajD7KHaHdEopNQibbCbvTpBqtHXSZRnqg==","ownerId":null,"publicKey":"pQECAyYgASFYIJOfmKPdiSL7oKgsvff3o4tX2Vj4w6TtxmT3RjvP40VkIlggMaOvodqHWghL0DrPMz74QIEaL+ShC0pLUanAy69LhPs="}

}

func ExampleRelyingParty_VerifyRegistrationCeremony() {
	ctx := context.Background()

	origin := "http://localhost:5000"
	storage := webauthn.NewInMemoryCredentialStorage()
	relyingParty := webauthn.NewRelyingParty(origin, storage)

	var options webauthn.PublicKeyCredentialCreationOptions
	_ = json.Unmarshal([]byte(`
		{
		  "rp": {
			"name": "Pomerium"
		  },
		  "user": {
			"displayName": "Test User",
			"name": "test-user",
			"id": "dGVzdC11c2Vy"
		  },
		  "pubKeyCredParams": [
			{
			  "type": "public-key",
			  "alg": -257
			},
			{
			  "type": "public-key",
			  "alg": -7
			}
		  ],
		  "authenticatorSelection": {
			"authenticatorAttachment": "cross-platform",
			"requireResidentKey": false
		  },
		  "attestation": "direct",
		  "challenge": "dGVzdC1jaGFsbGVuZ2U",
		  "timeout": 15000
		}
	`), &options)
	var response webauthn.PublicKeyCreationCredential
	_ = json.Unmarshal([]byte(`
		{
		  "id": "BOyUQxjpKJSR2VhsJok4FR8LIoZZ53QnrXxkiw5tzrp0cJuciBsxdIjabLjB6ebQMuKPqmMIPanM28HzGB9sig",
		  "rawId": "BOyUQxjpKJSR2VhsJok4FR8LIoZZ53QnrXxkiw5tzrp0cJuciBsxdIjabLjB6ebQMuKPqmMIPanM28HzGB9sig",
		  "response": {
		    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZEdWemRDMWphR0ZzYkdWdVoyVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9",
		    "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAIwctsPvNyXT6gEFJnqWlYqy_GBgNawLRrdZUwy8KpYqAiEAoQ6ct84cs9xyKo3v4c2HBGs1T7wg67oepLeiRa8vUG1jeDVjgVkBXTCCAVkwggEAoAMCAQICAQEwCgYIKoZIzj0EAwIwKDEVMBMGA1UEAxMMU2VjdXJpdHkgS2V5MQ8wDQYDVQQKEwZHb29nbGUwIhgPMjAwMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTIzNTk1OVowKDEVMBMGA1UEAxMMU2VjdXJpdHkgS2V5MQ8wDQYDVQQKEwZHb29nbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ_1ZtuIheQTnPrYNbFIME1flmt6RjmX7dUQbpOUwIl4lhN_I6gOiWBaocqrYWJlGVyXN4uYV31iKY73Zw1EjhaoxcwFTATBgsrBgEEAYLlHAIBAQQEAwIEMDAKBggqhkjOPQQDAgNHADBEAiBKHLlAEJFmo0of3IiO6Afg2kn8Rmn0wa4ml4ANfsBW9AIgauaLpiP9LGBRXYS7hq1B-GSzl40V8PR_k2HkZ76RDuxoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAE7JRDGOkolJHZWGwmiTgVHwsihlnndCetfGSLDm3OunRwm5yIGzF0iNpsuMHp5tAy4o-qYwg9qczbwfMYH2yKpQECAyYgASFYID1HLxI1bZD28OItYBsrBNkz8hr_YWX_sIht0GVmMNCcIlggze0LBzzUxMeF3sWcDzsHXr-hxGEQgwjZBjQg2dcdp7Y"
		  }
		}
	`), &response)

	credential, err := relyingParty.VerifyRegistrationCeremony(ctx, &options, &response)
	if err != nil {
		panic(err)
	}

	bs, _ := json.Marshal(credential)
	fmt.Println(string(bs))
	// Output: {"id":"BOyUQxjpKJSR2VhsJok4FR8LIoZZ53QnrXxkiw5tzrp0cJuciBsxdIjabLjB6ebQMuKPqmMIPanM28HzGB9sig==","ownerId":"dGVzdC11c2Vy","publicKey":"pQECAyYgASFYID1HLxI1bZD28OItYBsrBNkz8hr/YWX/sIht0GVmMNCcIlggze0LBzzUxMeF3sWcDzsHXr+hxGEQgwjZBjQg2dcdp7Y="}
}
