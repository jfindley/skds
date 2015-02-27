// Package crypto handles all the cryptographical functions for SKDS.
// auth.go handles authentication functions.
// crypto.go handles general purpose encryption/decryption.
// encoding.go handles encoding and decoding of generic binary data.
// x509.go handles x509 certificates and ECDSA keys.
package crypto

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
)

// Binary is a byte slice type.
// Used for any []byte data that needs to be sent across
// the wire, or read/written to disk.
type Binary []byte

// NewBinary creates a new *Binary from a []byte.
func NewBinary(in []byte) *Binary {
	b := new(Binary)
	*b = in
	return b
}

// Compare compares binary data in constant time.
func (b *Binary) Compare(data Binary) bool {
	if subtle.ConstantTimeCompare(*b, data) != 1 {
		return false
	}
	return true
}

// Encode encodes binary data in base64 form.
func (b *Binary) Encode() ([]byte, error) {
	encLen := base64.StdEncoding.EncodedLen(len(*b))

	enc := make([]byte, encLen)
	base64.StdEncoding.Encode(enc, *b)

	return enc, nil
}

// Decode decodes base64 data into a binary object.
func (b *Binary) Decode(data []byte) error {
	decLen := base64.StdEncoding.DecodedLen(len(data))

	dec := make([]byte, decLen)
	n, err := base64.StdEncoding.Decode(dec, data)
	if err != nil {
		return err
	}
	*b = dec[:n]
	return nil
}

// EncodeString encodes binary data directly into a string.
// Useful if sending the data in headers.
func (b *Binary) EncodeString() (string, error) {
	return base32.StdEncoding.EncodeToString(*b), nil
}

// DecodeString decodes binary data from a base64 string.
func (b *Binary) DecodeString(data string) error {
	var err error
	*b, err = base32.StdEncoding.DecodeString(data)
	return err
}
