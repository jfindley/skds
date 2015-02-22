package shared

import (
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
