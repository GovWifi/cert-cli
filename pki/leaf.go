package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

// LeafCommonName is the subject common name for a 1-based leaf index.
func LeafCommonName(index int) string {
	return fmt.Sprintf("GovWifi Leaf %d", index)
}

// CreateLeaf generates a new RSA key and an end-entity certificate named
// commonName, signed by issuerCert with issuerKey, valid from notBefore until notAfter.
func CreateLeaf(issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey, commonName string, notBefore, notAfter time.Time) (*CADetails, error) {
	privateKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	certPEM, err := CreateLeafCertificate(issuerCert, issuerKey, privateKey, commonName, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return newCADetails(privateKey, certPEM)
}

// CreateLeafCertificate returns a PEM-encoded end-entity certificate for
// commonName, signed by issuerCert with issuerKey and valid from notBefore until notAfter.
func CreateLeafCertificate(issuerCert *x509.Certificate, issuerKey *rsa.PrivateKey, leafKey *rsa.PrivateKey, commonName string, notBefore, notAfter time.Time) ([]byte, error) {
	template, err := newLeafTemplate(commonName, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}

	return encodeCertificatePEM(certDER), nil
}

func newLeafTemplate(commonName string, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{govWifiCountry},
			Organization: []string{govWifiOrganization},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}, nil
}
