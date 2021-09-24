package webauthn

// AuthenticatorFlagsSize is the number of bytes in the AuthenticatorFlags.
const AuthenticatorFlagsSize = 1

// AuthenticatorFlags are flags that indicate information about AuthenticatorData.
type AuthenticatorFlags byte

// UserPresent returns true if the user is "present".
func (flags AuthenticatorFlags) UserPresent() bool {
	return (flags & authenticatorFlagsUP) == authenticatorFlagsUP
}

// UserVerified returns true if the user is "verified".
func (flags AuthenticatorFlags) UserVerified() bool {
	return (flags & authenticatorFlagsUV) == authenticatorFlagsUV
}

// AttestedCredentialDataIncluded returns true if the AuthenticatorData has attested credential data.
func (flags AuthenticatorFlags) AttestedCredentialDataIncluded() bool {
	return (flags & authenticatorFlagsAT) == authenticatorFlagsAT
}

// ExtensionDataIncluded returns true if the AuthenticatorData has extension data.
func (flags AuthenticatorFlags) ExtensionDataIncluded() bool {
	return (flags & authenticatorFlagsED) == authenticatorFlagsED
}

const (
	authenticatorFlagsUP = 1 << iota
	_
	authenticatorFlagsUV
	_
	_
	_
	authenticatorFlagsAT
	authenticatorFlagsED
)
