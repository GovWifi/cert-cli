package pki

import "crypto/x509"

// ValidateSignedBy reports whether the certificate at certPath was signed by
// the certificate at issuerPath.
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

// ValidateSignedByPEM reports whether certPEM was signed by issuerPEM.
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

// CheckSignedBy reports whether cert was signed by issuer.
func CheckSignedBy(cert, issuer *x509.Certificate) error {
	return cert.CheckSignatureFrom(issuer)
}
