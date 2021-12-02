# Webauthn

[![Go Report Card](https://goreportcard.com/badge/github.com/pomerium/webauthn)](https://goreportcard.com/report/github.com/pomerium/webauthn) [![GoDoc](https://pkg.go.dev/badge/github.com/pomerium/webauthn?status.svg)](https://pkg.go.dev/github.com/pomerium/webauthn?tab=doc) [![Coverage Status](https://coveralls.io/repos/github/pomerium/webauthn/badge.svg)](https://coveralls.io/github/pomerium/webauthn) [![pomerium chat](https://img.shields.io/badge/chat-on%20slack-blue.svg?style=flat&logo=slack)](http://slack.pomerium.io) [![GitHub Actions](https://img.shields.io/github/workflow/status/pomerium/webauthn/Test?style=flat)](https://github.com/pomerium/webauthn/actions?query=workflow%3ATest) [![LICENSE](https://img.shields.io/github/license/pomerium/webauthn.svg)](https://github.com/pomerium/webauthn/blob/master/LICENSE)

This [Go library](https://pkg.go.dev/github.com/pomerium/webauthn) implements [WebAuthn](https://www.w3.org/TR/webauthn/)/[FIDO2](https://fidoalliance.org/fido2/) spec as a [relying party](https://www.w3.org/TR/webauthn/#relying-party), and includes:

- [registration](https://www.w3.org/TR/webauthn/#usecase-registration)
- [attestation](https://www.w3.org/TR/webauthn/#attestation)
- [authentication](https://www.w3.org/TR/webauthn/#usecase-authentication)
- [assertion](https://www.w3.org/TR/webauthn/#authentication-assertion)

## Code examples

## Demo apps

- See Pomerium's [verify](https://github.com/pomerium/verify) app for full examples of both [attestation](https://www.w3.org/TR/webauthn/#sctn-attestation) and [assertion](https://www.w3.org/TR/webauthn/#verifying-assertion).
