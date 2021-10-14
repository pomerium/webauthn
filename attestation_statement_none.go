package webauthn

// VerifyNoneAttestationStatement verifies that an AttestationObject's attestation statement is valid according to the
// "none" verification procedure.
func VerifyNoneAttestationStatement(
	attestationObject *AttestationObject,
	clientDataJSONHash ClientDataJSONHash,
) (*VerifyAttestationStatementResult, error) {
	return &VerifyAttestationStatementResult{
		Type: AttestationTypeNone,
	}, nil
}
