package main

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"

    "github.com/fxamacker/cbor/v2"
)

const (
    // FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
    FlagUserPresent AuthenticatorFlags = 1 << iota // Referred to as UP
    _                                              // Reserved
    // FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
    // by the authenticator using a biometric or PIN
    FlagUserVerified // Referred to as UV
    _                // Reserved
    _                // Reserved
    _                // Reserved
    // FlagAttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether
    // the authenticator added attested credential data.
    FlagAttestedCredentialData // Referred to as AT
    // FlagHasExtension Bit 10000000 in the byte sequence. Indicates if the authenticator data has extensions.
    FlagHasExtensions //  Referred to as ED
)

// AuthenticatorFlags A byte of information returned during during ceremonies in the
// authenticatorData that contains bits that give us information about the
// whether the user was present and/or verified during authentication, and whether
// there is attestation or extension data present. Bit 0 is the least significant bit.
type AuthenticatorFlags byte

// UserPresent returns if the UP flag was set
func (flag AuthenticatorFlags) UserPresent() bool {
    return (flag & FlagUserPresent) == FlagUserPresent
}

// UserVerified returns if the UV flag was set
func (flag AuthenticatorFlags) UserVerified() bool {
    return (flag & FlagUserVerified) == FlagUserVerified
}

// HasAttestedCredentialData returns if the AT flag was set
func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
    return (flag & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

// HasExtensions returns if the ED flag was set
func (flag AuthenticatorFlags) HasExtensions() bool {
    return (flag & FlagHasExtensions) == FlagHasExtensions
}

// AuthenticatorData From §6.1 of the spec.
// The authenticator data structure encodes contextual bindings made by the authenticator. These bindings
// are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
// assessment of the security properties of the authenticator. In one extreme case, the authenticator
// may be embedded in the client, and its bindings may be no more trustworthy than the client data.
// At the other extreme, the authenticator may be a discrete entity with high-security hardware and
// software, connected to the client over a secure channel. In both cases, the Relying Party receives
// the authenticator data in the same format, and uses its knowledge of the authenticator to make
// trust decisions.
//
// The authenticator data, at least during attestation, contains the Public PublicKey that the RP stores
// and will associate with the user attempting to register.
type AuthenticatorData struct {
    RPIDHash []byte                 `json:"rpid"`
    Flags    AuthenticatorFlags     `json:"flags"`
    Counter  uint32                 `json:"sign_count"`
    AttData  AttestedCredentialData `json:"att_data"`
    ExtData  []byte                 `json:"ext_data"`
}

type AttestedCredentialData struct {
    AAGUID       []byte `json:"aaguid"`
    CredentialID []byte `json:"credential_id"`
    // The raw credential public key bytes received from the attestation data
    CredentialPublicKey []byte `json:"public_key"`
}


const (
    minAuthDataLength     = 37
    minAttestedAuthLength = 55

    // https://w3c.github.io/webauthn/#attested-credential-data
    maxCredentialIDLength = 1023
)

// Unmarshal will take the raw Authenticator Data and marshalls it into AuthenticatorData for further validation.
// The authenticator data has a compact but extensible encoding. This is desired since authenticators can be
// devices with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
// The authenticator data structure is a byte array of 37 bytes or more, and is laid out in this table:
// https://www.w3.org/TR/webauthn/#table-authData
func (a *AuthenticatorData) Unmarshal(rawAuthData []byte) error {
    if minAuthDataLength > len(rawAuthData) {
        err := errors.New("Authenticator data length too short")
        // info := fmt.Sprintf("Expected data greater than %d bytes. Got %d bytes\n", minAuthDataLength, len(rawAuthData))
        return err
    }

    a.RPIDHash = rawAuthData[:32]
    a.Flags = AuthenticatorFlags(rawAuthData[32])
    a.Counter = binary.BigEndian.Uint32(rawAuthData[33:37])

    remaining := len(rawAuthData) - minAuthDataLength

    if a.Flags.HasAttestedCredentialData() {
        if len(rawAuthData) > minAttestedAuthLength {
            validError := a.unmarshalAttestedData(rawAuthData)
            if validError != nil {
                return validError
            }
            attDataLen := len(a.AttData.AAGUID) + 2 + len(a.AttData.CredentialID) + len(a.AttData.CredentialPublicKey)
            remaining = remaining - attDataLen
        } else {
            return errors.New("Attested credential flag set but data is missing")
        }
    } else {
        if !a.Flags.HasExtensions() && len(rawAuthData) != 37 {
            return errors.New("Attested credential flag not set")
        }
    }

    if a.Flags.HasExtensions() {
        if remaining != 0 {
            a.ExtData = rawAuthData[len(rawAuthData)-remaining:]
            remaining -= len(a.ExtData)
        } else {
            return errors.New("Extensions flag set but extensions data is missing")
        }
    }

    if remaining != 0 {
        return errors.New("Leftover bytes decoding AuthenticatorData")
    }

    return nil
}

// If Attestation Data is present, unmarshall that into the appropriate public key structure
func (a *AuthenticatorData) unmarshalAttestedData(rawAuthData []byte) error {
    a.AttData.AAGUID = rawAuthData[37:53]
    idLength := binary.BigEndian.Uint16(rawAuthData[53:55])
    if len(rawAuthData) < int(55+idLength) {
        return errors.New("Authenticator attestation data length too short")
    }
    if idLength > maxCredentialIDLength {
        return errors.New("Authenticator attestation data credential id length too long")
    }
    a.AttData.CredentialID = rawAuthData[55 : 55+idLength]
    a.AttData.CredentialPublicKey = unmarshalCredentialPublicKey(rawAuthData[55+idLength:])
    return nil
}

// Unmarshall the credential's Public PublicKey into CBOR encoding
func unmarshalCredentialPublicKey(keyBytes []byte) []byte {
    var m interface{}
    cbor.Unmarshal(keyBytes, &m)
    rawBytes, _ := cbor.Marshal(m)
    return rawBytes
}

// Verify on AuthenticatorData handles Steps 9 through 12 for Registration
// and Steps 11 through 14 for Assertion.
func (a *AuthenticatorData) Verify(rpIdHash, appIDHash []byte, userVerificationRequired bool) error {

    // Registration Step 9 & Assertion Step 11
    // Verify that the RP ID hash in authData is indeed the SHA-256
    // hash of the RP ID expected by the RP.
    if !bytes.Equal(a.RPIDHash[:], rpIdHash) && !bytes.Equal(a.RPIDHash[:], appIDHash) {
        return errors.New(fmt.Sprintf("RP Hash mismatch. Expected %x and Received %x\n", a.RPIDHash, rpIdHash))
    }

    // Registration Step 10 & Assertion Step 12
    // Verify that the User Present bit of the flags in authData is set.
    if !a.Flags.UserPresent() {
        return errors.New(fmt.Sprintln("User presence flag not set by authenticator"))
    }

    // Registration Step 11 & Assertion Step 13
    // If user verification is required for this assertion, verify that
    // the User Verified bit of the flags in authData is set.
    if userVerificationRequired && !a.Flags.UserVerified() {
        return errors.New(fmt.Sprintln("User verification required but flag not set by authenticator"))
    }

    // Registration Step 12 & Assertion Step 14
    // Verify that the values of the client extension outputs in clientExtensionResults
    // and the authenticator extension outputs in the extensions in authData are as
    // expected, considering the client extension input values that were given as the
    // extensions option in the create() call. In particular, any extension identifier
    // values in the clientExtensionResults and the extensions in authData MUST be also be
    // present as extension identifier values in the extensions member of options, i.e., no
    // extensions are present that were not requested. In the general case, the meaning
    // of "are as expected" is specific to the Relying Party and which extensions are in use.

    // This is not yet fully implemented by the spec or by browsers

    return nil
}