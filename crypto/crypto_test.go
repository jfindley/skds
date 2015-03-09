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
	key1 := new(Key)
	key2 := new(Key)

	err := key1.Generate()
	if err != nil {
		t.Fatal(err)
	}

	data, err := key1.Encode()
	if err != nil {
		t.Fatal(err)
	}

	err = key2.Decode(data)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(key1.Priv[:], key2.Priv[:]) != 0 {
		t.Error("Private key mismatch", key1.Priv, key2.Priv)
	}

	if bytes.Compare(key1.Pub[:], key2.Pub[:]) != 0 {
		t.Error("Public key mismatch")
	}

}

func TestKeyZero(t *testing.T) {
	key := new(Key)

	err := key.Generate()
	if err != nil {
		t.Fatal(err)
	}

	keyCopy := key

	key.Zero()

	if keyCopy.Pub != nil {
		t.Error("Public key not zeroed")
	}

	if keyCopy.Priv != nil {
		t.Error("Private key not zeroed")
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

func TestRandomInt(t *testing.T) {
	i, err := RandomInt()
	if err != nil {
		t.Fatal(err)
	}
	// Not definitiviely an error, but unlikely to happen unless there's a problem
	if i == 0 {
		t.Error("Random int returned 0")
	}
}
