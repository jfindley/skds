// Convience functions to handle encoding/decoding from various formats
// and other related functions, like hashing.

package shared

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

func HexEncode(in []byte) (out []byte) {
	out = make([]byte, hex.EncodedLen(len(in)))
	hex.Encode(out, in)
	return
}

func HexDecode(in []byte) (out []byte) {
	out = make([]byte, hex.DecodedLen(len(in)))
	hex.Decode(out, in)
	return
}

func CertEncode(in *x509.Certificate) (out []byte, err error) {
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: in.Raw})
	out = buf.Bytes()
	return
}

func CertDecode(in []byte) (out *x509.Certificate, err error) {
	p, _ := pem.Decode(in)
	if len(p.Bytes) == 0 {
		err = errors.New("Invalid cert data")
		return
	}
	out, err = x509.ParseCertificate(p.Bytes)
	return
}

func KeyEncode(in *ecdsa.PrivateKey) (out []byte, err error) {
	der, err := x509.MarshalECPrivateKey(in)
	if err != nil {
		return
	}
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der})
	out = buf.Bytes()
	return
}

func KeyDecode(in []byte) (out *ecdsa.PrivateKey, err error) {
	p, _ := pem.Decode(in)
	out, err = x509.ParseECPrivateKey(p.Bytes)
	return
}
