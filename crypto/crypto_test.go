package crypto

import (
	"bytes"
	"testing"
)

func isZero(data []byte) bool {
	for i := range data {
		if data[i] != byte(0) {
			return false
		}
	}
	return true
}

func TestKey(t *testing.T) {
	key := new(Key)

	pub := []byte("foo")
	priv := []byte("bar")

	key.New(pub, nil)
	key.SetPriv(priv)

	if !isZero(priv) {
		t.Error("Private key not zeroed")
	}

	// Just compare the first 3 bytes, as the array is a lot longer than our test slice
	if bytes.Compare(key.Pub[0:3], pub) != 0 {
		t.Error("Public key does not match")
	}

	if bytes.Compare(key.Priv[0:3], []byte("bar")) != 0 {
		t.Error("Private key does not match")
	}

	err := key.Generate()
	if err != nil {
		t.Error("Failed to generate key")
	}

}

func TestEncryption(t *testing.T) {
	payload := []byte("Test payload data")
	// Payload will be zeroed, copy it
	// We can't simply set test = payload as test will just point to payload
	test := make([]byte, len(payload))
	copy(test, payload)

	keyA := new(Key)
	keyB := new(Key)

	// Generate two sets of keys to simulate sending a message from A to B
	err := keyA.Generate()
	if err != nil {
		t.Fatal(err)
	}
	err = keyB.Generate()
	if err != nil {
		t.Fatal(err)
	}

	enc, err := Encrypt(payload, keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	if isZero(enc[24:]) {
		t.Fatal("Invalid nonce")
	}
	if !isZero(payload) {
		t.Fatal("Payload not zeroed after encryption")
	}

	dec, err := Decrypt(enc, keyB)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(test, dec) != 0 {
		t.Fatal("Decrypted payload does not match")
	}

	if _, err := Decrypt(enc, keyA); err == nil {
		t.Fatal("Payload sucessfully decrypted with wrong key")
	}

	// Make sure attempts to use nil data are caught
	defer func() {
		if r := recover(); r != nil {
			t.Fatal("Failed to handle null input, panicked")
		}
	}()
	nullKey := new(Key)
	if _, err := Encrypt(nil, nullKey, nil); err == nil {
		t.Fatal("No error thrown when null data supplied")
	}
	if _, err := Decrypt(nil, nullKey); err == nil {
		t.Fatal("Failed to handle null input")
	}
}
