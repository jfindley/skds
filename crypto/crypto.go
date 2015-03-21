// Package crypto handles all the cryptographical functions for SKDS.
// auth.go handles authentication functions.
// crypto.go handles general purpose encryption/decryption.
// encoding.go handles encoding and decoding of generic binary data.
// x509.go handles x509 certificates and ECDSA keys.
package crypto

import (
	"code.google.com/p/go.crypto/nacl/box"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
)

// Key is a keypair structure.
type Key struct {
	Pub  *[32]byte
	Priv *[32]byte
}

// Generate randomly generates a new keypair.
func (k *Key) Generate() (err error) {
	k.Pub, k.Priv, err = box.GenerateKey(rand.Reader)
	return
}

// Encode PEM-encodes a key to be written to disk.
func (k *Key) Encode() (data []byte, err error) {
	pub := pem.EncodeToMemory(&pem.Block{Type: "NACL PUBLIC KEY", Bytes: k.Pub[:]})
	if pub == nil {
		return nil, errors.New("Unable to encode key")
	}
	defer Zero(pub)

	priv := pem.EncodeToMemory(&pem.Block{Type: "NACL PRIVATE KEY", Bytes: k.Priv[:]})
	if priv == nil {
		return nil, errors.New("Unable to encode key")
	}
	defer Zero(priv)

	data = make([]byte, len(pub)+len(priv))
	copy(data[:len(pub)], pub)
	copy(data[len(pub):], priv)
	return
}

// Decode reads a PEM-encoded key.
func (k *Key) Decode(data []byte) (err error) {
	defer Zero(data)

	k.Pub = new([32]byte)
	k.Priv = new([32]byte)

	pub, data := pem.Decode(data)
	if pub.Type != "NACL PUBLIC KEY" {
		return errors.New("Invalid public key")
	}

	priv, _ := pem.Decode(data)
	if priv.Type != "NACL PRIVATE KEY" {
		return errors.New("Invalid private key")
	}

	if pub.Bytes != nil {
		for i := range pub.Bytes {
			k.Pub[i] = pub.Bytes[i]
		}
	}
	if priv.Bytes != nil {
		for i := range priv.Bytes {
			k.Priv[i] = priv.Bytes[i]
		}
	}
	return
}

// Zero wipes a key and dereferences the pointers.
func (k *Key) Zero() {
	if k.Priv != nil {
		for i := range k.Priv {
			k.Priv[i] ^= k.Priv[i]
		}
	}
	if k.Pub != nil {
		for i := range k.Pub {
			k.Pub[i] ^= k.Pub[i]
		}
	}
	k.Pub = nil
	k.Priv = nil
}

// Zero wipes binary data in memory.
func Zero(in Binary) {
	if in == nil {
		return
	}
	for i := range in {
		in[i] ^= in[i]

	}
	return
}

// We generate nonces randomly - chance of collision is negligable
// 24 byte length mandated by NaCL.
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

// Encrypt is a general asymmetric encryption function.
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

// Decrypt is a general asymmetric decryption
// Uses the public key enclosed in the payload for decryption.
func Decrypt(payload []byte, key *Key) (out []byte, err error) {
	if len(payload) <= 25 {
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

// RandomInt generates a random integer in the range 1..max int64
func RandomInt() (int64, error) {
	max := big.NewInt(1<<63 - 1)
	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return r.Int64(), err
}
