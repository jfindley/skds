package crypto

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
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

func PasswordHash(pass Binary) (hash Binary, err error) {
	hash = make([]byte, SaltLength+scryptLen)
	salt, err := generateSalt()
	if err != nil {
		return
	}
	copy(hash, salt)
	h, err := makeHash(pass, salt)
	if err != nil {
		return
	}
	copy(hash[SaltLength:], h)
	return
}

func NewPassword() (pass Binary, err error) {
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

func PasswordVerify(pass, hash Binary) (ok bool, err error) {
	ok = false
	if hash == nil || pass == nil {
		err = errors.New("Null input supplied")
		return
	}
	// Detect bad hash length
	if len(hash) != SaltLength+scryptLen {
		err = errors.New("Bad hash length")
		return
	}
	hchk, err := makeHash(pass, hash[0:SaltLength])
	if err != nil {
		err = errors.New("Failed to build test hash")
		return
	}
	if subtle.ConstantTimeCompare(hash[SaltLength:], hchk) != 1 {
		return
	}
	ok = true
	return
}

// MACs are in string format, because they're sent in header messages
// which require strings.

func NewMAC(key []byte, url string, msg []byte) string {
	m := hmac.New(sha256.New, key)

	m.Write(macData(url, msg))
	return base32.StdEncoding.EncodeToString(m.Sum(nil))
}

func VerifyMAC(key []byte, msgMac string, url string, msg []byte) (ok bool) {
	msgMacDec, err := base32.StdEncoding.DecodeString(msgMac)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(macData(url, msg))

	expMac := mac.Sum(nil)
	ok = hmac.Equal(msgMacDec, expMac)
	return
}

func macData(url string, msg []byte) []byte {
	msgContent := make([]byte, len(url)+len(msg))
	copy(msgContent[:len(url)], []byte(url))
	copy(msgContent[len(url):], msg)
	return msgContent
}
