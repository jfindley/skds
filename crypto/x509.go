// This is essentially a stub that allows us to generate a simple CA and certificate.
// Ultimately I'd like to expand this to provide full end to end x509 management, but
// that can wait for another day.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func GenKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// For self-signed certs, leave caCert nil
func GenCert(name string, isCa bool, years int, pubKey *ecdsa.PublicKey,
	privKey *ecdsa.PrivateKey, caCert *x509.Certificate) (cert *x509.Certificate, err error) {

	now := time.Now()

	template := x509.Certificate{
		// Serial must be unique - however there's no practical chance of collision here
		SerialNumber: new(big.Int).SetInt64(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:    now.Add(-5 * time.Minute).UTC(),
		NotAfter:     now.AddDate(years, 0, 0).UTC(),
		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	if isCa {
		template.BasicConstraintsValid = true
		template.IsCA = true
		template.MaxPathLen = 0
		template.KeyUsage = x509.KeyUsageCertSign
	}
	if caCert == nil {
		caCert = &template
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

func CaPool(cert *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(cert)
	return p
}
