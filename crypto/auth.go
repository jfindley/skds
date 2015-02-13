package crypto

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

const (
	PasswordCost   = 10
	MinPasswordLen = 8
	SaltLength     = 16
	scryptN        = 1 << 12
	scryptR        = 8
	scryptP        = 8
	scryptLen      = 32
	// This is just for auto-generated registration passwords
	// We include numbers twice to even the odds between the character classes a bit
	passwordChars = "01234567890123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func PasswordHash(pass []byte) (hash []byte, err error) {
	key := make([]byte, SaltLength+scryptLen)
	defer Zero(key)
	salt, err := generateSalt()
	if err != nil {
		return
	}
	copy(key, salt)
	h, err := makeHash(pass, salt)
	if err != nil {
		return
	}
	copy(key[SaltLength:], h)
	hash = HexEncode(key)
	return
}

func NewPassword() (pass []byte, err error) {
	pass = make([]byte, MinPasswordLen)
	r := new(big.Int)
	lim := big.NewInt(int64(len(passwordChars)))
	for i := 0; i < MinPasswordLen; i++ {
		r, err = rand.Int(rand.Reader, lim)
		if err != nil {
			return
		}
		v := int(r.Int64())
		pass[i] = []byte(passwordChars)[v]
	}
	return
}

func makeHash(pass, salt []byte) (hash []byte, err error) {
	hash, err = scrypt.Key(pass, salt, scryptN, scryptR, scryptP, scryptLen)
	return
}

func generateSalt() (salt []byte, err error) {
	salt = make([]byte, SaltLength)
	_, err = io.ReadFull(rand.Reader, salt)
	return
}

func PasswordVerify(pass, hash []byte) (ok bool, err error) {
	ok = false
	if hash == nil || pass == nil {
		err = errors.New("Null input supplied")
		return
	}
	dec := HexDecode(hash)
	// Detect bad hash length
	if len(dec) != SaltLength+scryptLen {
		err = errors.New("Bad hash length")
		return
	}
	hchk, err := makeHash(pass, dec[0:SaltLength])
	if err != nil {
		err = errors.New("Failed to build test hash")
		return
	}
	if subtle.ConstantTimeCompare(dec[SaltLength:], hchk) != 1 {
		return
	}
	ok = true
	return
}

func NewMAC(key, msg []byte) (mac []byte) {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	mac = HexEncode(m.Sum(nil))
	return
}

func VerifyMAC(key, msgMac, msg []byte) (ok bool) {
	msgMacDec := HexDecode(msgMac)
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	expMac := mac.Sum(nil)
	ok = hmac.Equal(msgMacDec, expMac)
	return
}
