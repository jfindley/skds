package shared

import (
	"crypto/subtle"
	"encoding/base64"
	"io/ioutil"
)

type FileData interface {
	Encode() ([]byte, error)
	Decode([]byte) error
}

func Write(d FileData, path string) error {
	data, err := d.Encode()
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path, data, 0600)
}

func Read(d FileData, path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	return d.Decode(data)
}

type Binary []byte

func (b *Binary) New(data []byte) {
	*b = data
	return
}

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
