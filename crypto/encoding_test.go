package crypto

import (
	"testing"
)

func TestNewBinary(t *testing.T) {
	in := []byte("test")
	bin := NewBinary(in)

	if !bin.Compare(in) {
		t.Error("New binary not created correctly")
	}
}

func TestBinary(t *testing.T) {
	var b1, b2 Binary

	testData := []byte("Some test data")

	b1 = testData

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
func TestBinaryString(t *testing.T) {
	var b1, b2 Binary

	testData := []byte("Some test data")

	b1 = testData

	data, err := b1.EncodeString()
	if err != nil {
		t.Fatal(err)
	}

	if len(data) == 0 {
		t.Fatal("Zero bytes encoded")
	}

	err = b2.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}

	if !b2.Compare(testData) {
		t.Error("Data does not match")
	}
}
