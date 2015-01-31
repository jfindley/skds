package crypto

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

type Key struct {
	Pub  *[32]byte
	Priv *[32]byte
}

func (k *Key) Zero() {
	for i := range k.Priv {
		k.Priv[i] ^= k.Priv[i]

	}
	return
}

func (k *Key) New(pub, priv []byte) {
	k.Pub = new([32]byte)
	k.Priv = new([32]byte)
	if pub != nil {
		for i := range pub {
			k.Pub[i] = pub[i]
		}
	}
	if priv != nil {
		for i := range priv {
			k.Priv[i] = priv[i]
		}
	}
	Zero(priv)
	return
}

func (k *Key) SetPriv(priv []byte) {
	if priv != nil {
		for i := range priv {
			k.Priv[i] = priv[i]
		}
	}
	Zero(priv)
	return
}

func (k *Key) Generate() (err error) {
	k.Pub, k.Priv, err = box.GenerateKey(rand.Reader)
	return
}

// Zero out a byte slice.
func Zero(in []byte) {
	if in == nil {
		return
	}
	for i := range in {
		in[i] ^= in[i]

	}
	return
}

// We generate nonces randomly - chance of collision is negligable
// 24 byte length mandated by NaCL
func generateNonce() (nonce *[24]byte, err error) {
	// Allocate the memory before we try to use it
	nonce = new([24]byte)
	buf := make([]byte, 24)
	n, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return
	}
	if n != 24 {
		return nil, errors.New("Bad nonce length")
	}
	copy(nonce[:], buf)
	return
}

// Asymmetric encryption functions
// The public part of 'key' is enclosed in the output as a signing key, and is
// needed in order to decrypt the payload.
func Encrypt(payload []byte, key *Key, pubkey *Key) (out []byte, err error) {
	if len(payload) == 0 {
		return nil, errors.New("Null input")
	}

	defer Zero(payload)

	// Nonce + pubkey + message + overhead
	out = make([]byte, 24+32+len(payload)+box.Overhead)

	nonce, err := generateNonce()
	if err != nil {
		return
	}
	copy(out, nonce[:])
	copy(out[24:56], key.Pub[:])
	copy(out[56:], box.Seal(nil, payload, nonce, pubkey.Pub, key.Priv))

	return
}

func Decrypt(payload []byte, key *Key) (out []byte, err error) {
	if len(payload) < 25 {
		return nil, errors.New("Null input")
	}
	// Read nonce from start of payload
	var nonce [24]byte
	copy(nonce[:], payload[:24])

	// Read the signing key
	var pubkey [32]byte
	copy(pubkey[:], payload[24:56])

	out, ok := box.Open(nil, payload[56:], &nonce, &pubkey, key.Priv)
	if !ok {
		return nil, errors.New("Unable to decrypt payload")
	}
	return
}

func RandomInt() (int64, error) {
	max := big.NewInt(1<<63 - 1)
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return r.Int64(), err
}
