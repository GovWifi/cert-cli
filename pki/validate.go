package pki

import "crypto/x509"

func ValidateSignedBy(certPath, issuerPath string) error {
	cert, err := LoadCertificate(certPath)
	if err != nil {
		return err
	}

	issuer, err := LoadCertificate(issuerPath)
	if err != nil {
		return err
	}

	return CheckSignedBy(cert, issuer)
}

func ValidateSignedByPEM(certPEM, issuerPEM []byte) error {
	cert, err := PemToCertificate(certPEM)
	if err != nil {
		return err
	}

	issuer, err := PemToCertificate(issuerPEM)
	if err != nil {
		return err
	}

	return CheckSignedBy(cert, issuer)
}

func CheckSignedBy(cert, issuer *x509.Certificate) error {
	return cert.CheckSignatureFrom(issuer)
}
