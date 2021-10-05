package android

// SafetyNetClaims are fields available in the JWT payload of a SafetyNet attestation response as defined by:
// https://developer.android.com/training/safetynet/attestation#use-response-server
type SafetyNetClaims struct {
	TimestampMS                int      `json:"timestampMs"`
	Nonce                      []byte   `json:"nonce"`
	APKPackageName             string   `json:"apkPackageName"`
	APKCertificateDigestSHA256 [][]byte `json:"apkCertificateDigestSha256"`
	CTSProfileMatch            bool     `json:"ctsProfileMatch"`
	BasicIntegrity             bool     `json:"basicIntegrity"`
	EvaluationType             string   `json:"evaluationType"`
}
