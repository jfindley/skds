// Convience functions to handle encoding/decoding.

package crypto

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
)

type Binary []byte

func (b *Binary) Compare(data []byte) bool {
	if subtle.ConstantTimeCompare(*b, data) != 1 {
		return false
	}
	return true
}

func (b *Binary) Encode() ([]byte, error) {
	encLen := base64.StdEncoding.EncodedLen(len(*b))

	enc := make([]byte, encLen)
	base64.StdEncoding.Encode(enc, *b)

	return enc, nil
}

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

func (b *Binary) EncodeString() (string, error) {
	return base32.StdEncoding.EncodeToString(*b), nil
}

func (b *Binary) DecodeString(data string) error {
	var err error
	*b, err = base32.StdEncoding.DecodeString(data)
	return err
}
