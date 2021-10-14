package webauthn

import _ "embed"

// AppleWebAuthnRootCAPEM is the Apple WebAuthn Root CA taken from:
// https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
//go:embed files/Apple_WebAuthn_Root_CA.pem
var AppleWebAuthnRootCAPEM []byte
