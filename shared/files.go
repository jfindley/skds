package shared

import (
	"crypto/subtle"
	"io/ioutil"

	"github.com/jfindley/skds/crypto"
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
	return crypto.HexEncode(*b), nil
}

func (b *Binary) Decode(data []byte) error {
	*b = crypto.HexDecode(data)
	return nil
}
