package crypto

import (
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

var msg []byte

func init() {
	msg = make([]byte, 1024)
	_, err := io.ReadFull(rand.Reader, msg)
	if err != nil {
		panic(err)
	}
}

func TestPasswordHash(t *testing.T) {
	pass := []byte("testing password")

	hash, err := PasswordHash(pass)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) == 0 {
		t.Fatal("Zero-length hash returned")
	}
	ok, err := PasswordVerify(pass, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Password did not verify correctly")
	}
}

func TestNewPassword(t *testing.T) {
	pass, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}

	for i := range pass {
		if !strings.Contains(passwordChars, string(pass[i])) {
			t.Error("Bad character in generated password")
		}
	}

	if len(pass) < MinPasswordLen {
		t.Error("Generated password too short")
	}
}

func TestMac(t *testing.T) {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatal(err)
	}

	mac := NewMAC(key, "/path", msg)

	ok := VerifyMAC(key, mac, "/path", msg)
	if !ok {
		t.Error("Message not verified")
	}
}
