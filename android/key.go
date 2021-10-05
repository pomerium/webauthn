// Package android contains helper functions and types for Android.
package android

import "encoding/asn1"

// AuthorizationList is the keymaster authorization list.
type AuthorizationList struct {
	Purpose                     KeyMasterPurposeSet `asn1:"tag:1,explicit,set,optional"`
	Algorithm                   int                 `asn1:"tag:2,explicit,optional"`
	KeySize                     int                 `asn1:"tag:3,explicit,optional"`
	Digest                      []int               `asn1:"tag:5,explicit,set,optional"`
	Padding                     []int               `asn1:"tag:6,explicit,set,optional"`
	ECCurve                     int                 `asn1:"tag:10,explicit,optional"`
	RSAPublicExponent           int                 `asn1:"tag:200,explicit,optional"`
	RollbackResistance          asn1.Flag           `asn1:"tag:303,explicit,optional"`
	ActiveDateTime              int                 `asn1:"tag:400,explicit,optional"`
	OriginationExpireDateTime   int                 `asn1:"tag:401,explicit,optional"`
	UsageExpireDateTime         int                 `asn1:"tag:402,explicit,optional"`
	NoAuthRequired              asn1.Flag           `asn1:"tag:503,explicit,optional"`
	UserAuthType                int                 `asn1:"tag:504,explicit,optional"`
	AuthTimeout                 int                 `asn1:"tag:505,explicit,optional"`
	AllowWhileOnBody            asn1.Flag           `asn1:"tag:506,explicit,optional"`
	TrustedUserPresenceRequired asn1.Flag           `asn1:"tag:507,explicit,optional"`
	TrustedConfirmationRequired asn1.Flag           `asn1:"tag:508,explicit,optional"`
	UnlockedDeviceRequired      asn1.Flag           `asn1:"tag:509,explicit,optional"`
	AllApplications             asn1.Flag           `asn1:"tag:600,explicit,optional"`
	ApplicationID               asn1.Flag           `asn1:"tag:601,explicit,optional"`
	CreationDateTime            int                 `asn1:"tag:701,explicit,optional"`
	Origin                      KeyOrigin           `asn1:"tag:702,explicit,optional"`
	RootOfTrust                 RootOfTrust         `asn1:"tag:704,explicit,optional"`
	OSVersion                   int                 `asn1:"tag:705,explicit,optional"`
	OSPatchLevel                int                 `asn1:"tag:706,explicit,optional"`
	AttestationApplicationID    []byte              `asn1:"tag:709,explicit,optional"`
	AttestationIDBrand          []byte              `asn1:"tag:710,explicit,optional"`
	AttestationIDDevice         []byte              `asn1:"tag:711,explicit,optional"`
	AttestationIDProduct        []byte              `asn1:"tag:712,explicit,optional"`
	AttestationIDSerial         []byte              `asn1:"tag:713,explicit,optional"`
	AttestationIDIMEID          []byte              `asn1:"tag:714,explicit,optional"`
	AttestationIDMEID           []byte              `asn1:"tag:715,explicit,optional"`
	AttestationIDManufacturer   []byte              `asn1:"tag:716,explicit,optional"`
	AttestationIDModel          []byte              `asn1:"tag:717,explicit,optional"`
	VendorPatchLevel            int                 `asn1:"tag:718,explicit,optional"`
	BootPatchLevel              int                 `asn1:"tag:719,explicit,optional"`
}

// A KeyDescription describes an android hardware key.
type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeyMasterVersion         int
	KeyMasterSecurityLevel   SecurityLevel
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         AuthorizationList
	TeeEnforced              AuthorizationList
}

// UnmarshalKeyDescription unmarshals an ASN.1 encoded key description from a slice of bytes.
func UnmarshalKeyDescription(raw []byte) (keyDescription *KeyDescription, remaining []byte, err error) {
	keyDescription = new(KeyDescription)
	remaining, err = asn1.Unmarshal(raw, keyDescription)
	return keyDescription, remaining, err
}

// Marshal marshals an android key description to an ASN.1 encoded slice of bytes.
func (keyDescription KeyDescription) Marshal() ([]byte, error) {
	return asn1.Marshal(keyDescription)
}

// A KeyMasterPurpose describe the purpose of a key (or pair).
type KeyMasterPurpose = int

// keymaster purposes
const (
	KeyMasterPurposeEncrypt KeyMasterPurpose = iota
	KeyMasterPurposeDecrypt
	KeyMasterPurposeSign
	KeyMasterPurposeVerify
	KeyMasterPurposeDeriveKey
	KeyMasterPurposeWrap
	KeyMasterPurposeAgreeKey
	KeyMasterPurposeAttestKey
)

// A KeyMasterPurposeSet is a set of key master purposes.
type KeyMasterPurposeSet []KeyMasterPurpose

// Has returns true if the set contains the given purpose.
func (set KeyMasterPurposeSet) Has(purpose KeyMasterPurpose) bool {
	for _, p := range set {
		if p == purpose {
			return true
		}
	}
	return false
}

// A KeyOrigin describes the origin of a key as defined in:
// https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h#315
type KeyOrigin = int

// key origins
const (
	KeyOriginGenerated KeyOrigin = iota
	KeyOriginDerived
	KeyOriginImported
	KeyOriginUnknown
)

// RootOfTrust described the verification state of a device's boot.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
	VerifiedBootHash  []byte
}

// SecurityLevel indicates the level of security.
type SecurityLevel = asn1.Enumerated

// security levels
const (
	SecurityLevelSoftware SecurityLevel = iota
	SecurityLevelTrustedEnvironment
	SecurityLevelStrongBox
)

// A VerifiedBootState indicates the state of the verified boot.
type VerifiedBootState = asn1.Enumerated

// verified boot states
const (
	VerifiedBootStateVerified VerifiedBootState = iota
	VerifiedBootStateSelfSigned
	VerifiedBootStateUnverified
	VerifiedBootStateFailed
)
