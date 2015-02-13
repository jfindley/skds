package crypto

import (
	"bytes"
	"testing"
)

func TestHex(t *testing.T) {
	testData := []byte("this is some test data")
	hex := HexEncode(testData)
	if bytes.Compare(testData, HexDecode(hex)) != 0 {
		t.Fatal("Hex encode/decode did not preserve data")
	}
}
