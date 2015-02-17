package shared

import (
	"bytes"
	"os"
	"testing"
)

var tmpfile = "/tmp/skdsfiletest"

type testFile struct {
	data []byte
}

func (t *testFile) Encode() ([]byte, error) {
	return t.data, nil
}

func (t *testFile) Decode(in []byte) error {
	t.data = in
	return nil
}

func TestFiles(t *testing.T) {
	origFile := new(testFile)
	newFile := new(testFile)
	origFile.data = []byte("test data")

	defer os.Remove(tmpfile)

	err := Write(origFile, tmpfile)
	if err != nil {
		t.Fatal(err)
	}

	err = Read(newFile, tmpfile)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(origFile.data, newFile.data) != 0 {
		t.Error("Files do not match")
	}
}

func TestBinary(t *testing.T) {
	b1 := new(Binary)
	b2 := new(Binary)

	testData := []byte("Some test data")

	b1.New(testData)

	data, err := b1.Encode()
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Fatal("Zero bytes encoded")
	}

	err = b2.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if !b2.Compare(testData) {
		t.Error("Data does not match")
	}
}
