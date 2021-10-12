package fido

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalMetadataBLOBPayload(t *testing.T) {
	// this rawJWT comes from the spec:
	// https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html
	bs, err := os.ReadFile("./testdata/spec-blob.jwt")
	require.NoError(t, err)
	rawJWT := strings.NewReplacer("\t", "", " ", "", "\r", "", "\n", "").Replace(string(bs))

	rootPEM, err := os.ReadFile("./testdata/spec-root-ca.pem")
	require.NoError(t, err)
	rootCA := x509.NewCertPool()
	rootCA.AppendCertsFromPEM(rootPEM)

	payload, err := UnmarshalMetadataBLOBPayload(rawJWT, WithRootCA(rootCA))
	assert.NoError(t, err)
	assert.Equal(t, &MetadataBLOBPayload{
		LegalHeader: "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at " +
			"https://fidoalliance.org/metadata/metadata-legal-terms/",
		No:         15,
		NextUpdate: "2020-03-30",
		Entries: []MetadataBLOBPayloadEntry{
			{
				AAID: "1234#5678",
				MetadataStatement: MetadataStatement{
					LegalHeader:          "https://fidoalliance.org/metadata/metadata-statement-legal-header/",
					AAID:                 "1234#5678",
					Description:          "FIDO Alliance Sample UAF Authenticator",
					AuthenticatorVersion: 2,
					ProtocolFamily:       "uaf",
					Schema:               3,
					UPV: []Version{
						{Major: 1, Minor: 0},
						{Major: 1, Minor: 1},
					},
					AuthenticationAlgorithms: []string{"secp256r1_ecdsa_sha256_raw"},
					PublicKeyAlgAndEncodings: []string{"ecc_x962_raw"},
					AttestationTypes:         []string{"basic_full"},
					UserVerificationDetails: []VerificationMethodANDCombinations{{
						VerificationMethodDescriptor{
							UserVerificationMethod: "fingerprint_internal",
							BADesc: BiometricAccuracyDescriptor{
								SelfAttestedFAR: 0.00002,
								MaxTemplates:    5,
								MaxRetries:      5,
								BlockSlowdown:   30,
							},
						},
					}},
					KeyProtection:        []string{"hardware", "tee"},
					IsKeyRestricted:      true,
					MatcherProtection:    []string{"tee"},
					CryptoStrength:       128,
					AttachmentHint:       []string{"internal"},
					TCDisplay:            []string{"any", "tee"},
					TCDisplayContentType: "image/png",
					TCDisplayPNGCharacteristics: []DisplayPNGCharacteristicsDescriptor{{
						Width:     320,
						Height:    480,
						BitDepth:  16,
						ColorType: 2,
					}},
					AttestationRootCertificates: []string{
						"MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMMF1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMyWjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwNRklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8gQWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFbC0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkriVdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XNlQ==",
					},
					Icon: "data:image/png;base64,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",
				},
				StatusReports: []StatusReport{
					{
						Status:        AuthenticatorStatusFIDOCertified,
						EffectiveDate: "2014-01-04",
					},
				},
				TimeOfLastStatusChange: "2014-01-04",
			},
			{
				AAGUID: AAGUID{0x01, 0x32, 0xD1, 0x10, 0xBF, 0x4E, 0x42, 0x08, 0xA4, 0x03, 0xAB, 0x4F, 0x5F, 0x12, 0xEF, 0xE5},
				MetadataStatement: MetadataStatement{
					LegalHeader:          "https://fidoalliance.org/metadata/metadata-statement-legal-header/",
					AAGUID:               AAGUID{0x01, 0x32, 0xD1, 0x10, 0xBF, 0x4E, 0x42, 0x08, 0xA4, 0x03, 0xAB, 0x4F, 0x5F, 0x12, 0xEF, 0xE5},
					Description:          "FIDO Alliance Sample FIDO2 Authenticator",
					AuthenticatorVersion: 5,
					ProtocolFamily:       "fido2",
					Schema:               3,
					UPV: []Version{
						{Major: 1, Minor: 0},
					},
					AuthenticationAlgorithms: []string{"secp256r1_ecdsa_sha256_raw", "rsassa_pkcsv15_sha256_raw"},
					PublicKeyAlgAndEncodings: []string{"cose"},
					AttestationTypes:         []string{"basic_full"},
					UserVerificationDetails: []VerificationMethodANDCombinations{
						{
							VerificationMethodDescriptor{
								UserVerificationMethod: "none",
							},
						},
						{
							VerificationMethodDescriptor{
								UserVerificationMethod: "presence_internal",
							},
						},
						{
							VerificationMethodDescriptor{
								UserVerificationMethod: "passcode_external",
								CADesc: CodeAccuracyDescriptor{
									Base:      10,
									MinLength: 4,
								},
							},
						},
						{
							VerificationMethodDescriptor{
								UserVerificationMethod: "passcode_external",
								CADesc: CodeAccuracyDescriptor{
									Base:      10,
									MinLength: 4,
								},
							},
							VerificationMethodDescriptor{
								UserVerificationMethod: "presence_internal",
							},
						},
					},
					TCDisplay:         []string{},
					KeyProtection:     []string{"hardware", "secure_element"},
					MatcherProtection: []string{"on_chip"},
					CryptoStrength:    128,
					AttachmentHint:    []string{"external", "wired", "wireless", "nfc"},
					AttestationRootCertificates: []string{
						"MIICPTCCAeOgAwIBAgIJAOuexvU3Oy2wMAoGCCqGSM49BAMCMHsxIDAeBgNVBAMMF1NhbXBsZSBBdHRlc3RhdGlvbiBSb290MRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMREwDwYDVQQLDAhVQUYgVFdHLDESMBAGA1UEBwwJUGFsbyBBbHRvMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwHhcNMTQwNjE4MTMzMzMyWhcNNDExMTAzMTMzMzMyWjB7MSAwHgYDVQQDDBdTYW1wbGUgQXR0ZXN0YXRpb24gUm9vdDEWMBQGA1UECgwNRklETyBBbGxpYW5jZTERMA8GA1UECwwIVUFGIFRXRywxEjAQBgNVBAcMCVBhbG8gQWx0bzELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH8hv2D0HXa59/BmpQ7RZehL/FMGzFd1QBg9vAUpOZ3ajnuQ94PR7aMzH33nUSBr8fHYDrqOBb58pxGqHJRyX/6NQME4wHQYDVR0OBBYEFPoHA3CLhxFbC0It7zE4w8hk5EJ/MB8GA1UdIwQYMBaAFPoHA3CLhxFbC0It7zE4w8hk5EJ/MAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAJ06QSXt9ihIbEKYKIjsPkriVdLIgtfsbDSu7ErJfzr4AiBqoYCZf0+zI55aQeAHjIzA9Xm63rruAxBZ9ps9z2XNlQ==",
					},
					Icon: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAE8AAAAvCAYAAACiwJfcAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAahSURBVGhD7Zr5bxRlGMf9KzTB8AM/YEhE2W7pQZcWKKBclSpHATlELARE7kNECCA3FkWK0CKKSCFIsKBcgVCDWGNESdAYidwgggJBiRiMhFc/4wy8884zu9NdlnGTfZJP2n3nO++88933fveBBx+PqCzJkTUvBbLmpUDWvBTImpcCSZvXLCdX9R05Sk19bb5atf599fG+/erA541q47aP1LLVa9SIyVNUi8Ii8d5kGTsi30NFv7ai9n7QZPMwbdys2erU2XMqUdy8+ZcaNmGimE8yXN3RUd3a18nF0fUlovZ+0CTzWpd2Vj+eOm1bEyy6Dx4i5pUMGWveo506q227dtuWBIuffr6oWpV0FPNLhow1751Nm21LvPH3rVtWjfz66Lfql8tX7FRl9YFSXsmSseb9ceOGbYk7MNUcGPg8ZsbMe9rfQUaaV/JMX9sqdzDCSvp0kZHmTZg9x7bLHcMnThb16eJ+mVfQq8yaUZQNG64iXZ+0/kq6uOZFO0QtatdWKfXnRQ99Bj91R5OIFnk54jN0mkUiqlO3XDW+Ml+98mKB6tW7rWpZcPc+0zg4tLrYlUc86E6eGDjIMubVpcusearfgIYGRk6brhZVr/JcHzooL7550jedLExopWcApi2ZUqhu7JLvrVsQU81zkzOPeemMRYvVuQsX7PbiDQY5JvZonftK+1VY8H9utx530h0ob+jmRYqj6ouaYvEenW/WlYjp8cwbMm682tPwqW1R4tj/2SH13IRJYl4moZvXpiSqDr7dXtQHxa/PK3/+BWsK1dTgHu6V8tQJ3bwFkwpFrUOQ50s1r3levm8zZcq17+BBaw7K8lEK5qzkYeark9A8p7P3GzDK+nd3DQow+6UC8SVN82iuv38im7NtaXtV1CVq6Rgw4pksmbdi3bu2De7YfaBBxcqfvqPrUjFQNTQ22lfdUVVT68rTJKF5DnSmUjgdqg4mSS9pmsfDJR3G6ToH0iW9aV7LWLHYXKllTDt0LTAtkYIaamp1QjVv++uyGUxVdJ0DNVXSm+b1qRxpl84ddfX1Lp1O/d69tsod0vs5hGre9xu8o+fpLR1cGhNTD6Z57C9KMWXefJdOZ94bb9oqd1ROnS7qITTzHimMqivbO3g0DdVyk3WQBhBztK35YKNdOnc8O3acS6fDZFgKaXLsEJp5rdrliBqp89cJcs/m7Tvs0rkjGfN4b0kPoZn3UJuIOrnZ22yP1fmvUx+O5gSqebV1m+zSuYNVhq7TWbDiLVvljplLlop6CLXP+2qtvGLIL/1vimISdMBgzSoFZyu6Tqd+jzxgsPaV9BCqee/NjYk6v6lK9cwiUc/STtf1HDpM3b592y7h3Thx5ozK69HLpYWuAwaqS5cv26q7ceb8efVYaReP3iFU8zj1knSwZXHMmnCjY0Ogalo7UQfSCM3qQQr2H/XFP7ssXx45Yl91ByeCep4moZoH+1fG3xD4tT7x8kwyj8nwb9ev26V0B6d+7H4zKvudAH537FjqyzOHdJnHEuzmXq/WjxObvNMbv7nhywsX2aVsWtC8+48aLeapE7p5wKZi0A2AQRV5nvR4E+uJc+b61kApqInxBgmd/4V5QP/mt18HDC7sRHftmeu5lmhV0rn/ALX232bqd4BFnDx7Vi1cWS2uff0IbB47qexxmUj9QutYjupd3tYD6abWBBMrh+apNbOKrNF1+ugCa4riXGfwMPPtViavhU3YMOAAnuUb/R07L0yOSeOadE88ApsXFGff30ynhlJgM51CU6vN9EzgnpvHBFUyiVraePiwJ53DF5ZTZnomENg85kNUd2oJi2Wpr4OmmkfN4x4zHfiVFc8Dv8NzuhNqOidilGvA6DGueZwO78AAQn6ciEk6+rw5VcvjvqNDYPOoIUwaKShrxAuXLlkH4aYuGfMYDc10WF5Ta31hPJOfcUhrU/JlINi6c6elRYdBpo6++Yfjx61lGNfRm4MD5rJ1j3FoGHnjDSBNarYUgMLyMszKpb7tXpoHfPs8h3Wp1LzNfNk54XxC1wDGUmYzXYefh6z/cKtVm4EBxa9VQGDzYr3LrUMRjHEKkk7zaFKYQA2hGQU1z+85NFWpXDrkz3vx10GqxQ6BzeNboBk5n8k4nebRh+k1hWfxTF0D1EyWUs5nv+dgQqKaxzuCdE0isHl02NQ8ah0mXr12La3m0f9wik9+wLNTMY/86MPo8yi31OfxmT6PWoqG9+DZukYna56mSZt5WWSy5qVA1rwUyJqXAlnzkiai/gHSD7RkTyihogAAAABJRU5ErkJggg==",
					SupportedExtensions: []ExtensionDescriptor{
						{
							ID: "hmac-secret",
						},
						{
							ID: "credProtect",
						},
					},
					AuthenticatorGetInfo: AuthenticatorGetInfo{
						"aaguid": "0132d110bf4e4208a403ab4f5f12efe5",
						"algorithms": []interface{}{
							map[string]interface{}{
								"alg":  -7.0,
								"type": "public-key",
							},
							map[string]interface{}{
								"alg":  -257.0,
								"type": "public-key",
							},
						},
						"defaultCredProtect": 2.0,
						"extensions": []interface{}{
							"credProtect",
							"hmac-secret",
						},
						"firmwareVersion":              5.0,
						"maxAuthenticatorConfigLength": 1024.0,
						"maxCredentialCountInList":     16.0,
						"maxCredentialIdLength":        128.0,
						"maxMsgSize":                   1200.0,
						"options": map[string]interface{}{
							"clientPin": "true",
							"config":    "false",
							"plat":      "false",
							"rk":        "true",
							"up":        "true",
							"uv":        "true",
							"uvToken":   "false",
						},
						"pinUvAuthProtocols": []interface{}{1.0},
						"transports":         []interface{}{"usb", "nfc"},
						"versions":           []interface{}{"U2F_V2", "FIDO_2_0"},
					},
				},
				StatusReports: []StatusReport{
					{
						Status:        AuthenticatorStatusFIDOCertified,
						EffectiveDate: "2019-01-04",
					},
					{
						Status:                           AuthenticatorStatusFIDOCertifiedL1,
						EffectiveDate:                    "2020-11-19",
						CertificationDescriptor:          "FIDO Alliance Sample FIDO2 Authenticator",
						CertificateNumber:                "FIDO2100020151221001",
						CertificationPolicyVersion:       "1.0.1",
						CertificationRequirementsVersion: "1.0.1",
					},
				},
				TimeOfLastStatusChange: "2019-01-04",
			},
		},
	}, payload)
}
