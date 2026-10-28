package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"
)

const (
	govWifiCountry      = "GB"
	govWifiOrganization = "GovWifi"
	RootCN              = "GovWifi Root CA"
	IntermediateCN      = "GovWifi Intermediate CA"
	// MaxLeafCount is the most leaf certificates CreateChain will issue.
	MaxLeafCount = 100
)

var (
	RootExpiry         = time.Now().Add(10 * 365 * 24 * time.Hour)
	IntermediateExpiry = time.Now().Add(5 * 365 * 24 * time.Hour)
	LeafExpiry         = time.Now().Add(365 * 24 * time.Hour)
)

// CADetails is an in-memory CA key pair and certificate.
type CADetails struct {
	Key           *rsa.PrivateKey
	Cert          *x509.Certificate
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	CertPEM       []byte
}

// CreateRootCA generates a new RSA key and a self-signed GovWifi root CA
// certificate valid from notBefore until notAfter.
func CreateRootCA(notBefore, notAfter time.Time) (*CADetails, error) {
	return CreateRootCAWithSubject(govWifiOrganization, RootCN, notBefore, notAfter)
}

// CreateRootCAWithSubject generates a new RSA key and a self-signed root CA
// certificate with the given organization and common name.
func CreateRootCAWithSubject(organization, commonName string, notBefore, notAfter time.Time) (*CADetails, error) {
	privateKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	certPEM, err := createSelfSignedCertificate(privateKey, organization, commonName, nil, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return newCADetails(privateKey, certPEM)
}

// CreateIntermediateCA generates a new RSA key and a GovWifi intermediate CA
// certificate signed by rootCert with rootKey, valid from notBefore until notAfter.
func CreateIntermediateCA(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, notBefore, notAfter time.Time) (*CADetails, error) {
	return CreateIntermediateCAWithSubject(rootCert, rootKey, govWifiOrganization, IntermediateCN, notBefore, notAfter)
}

// CreateIntermediateCAWithSubject generates a new RSA key and an intermediate CA
// certificate with the given organization and common name, signed by rootCert.
func CreateIntermediateCAWithSubject(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, organization, commonName string, notBefore, notAfter time.Time) (*CADetails, error) {
	privateKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	certPEM, err := createIntermediateCertificate(rootCert, rootKey, privateKey, organization, commonName, notBefore, notAfter)
	if err != nil {
		return nil, err
	}

	return newCADetails(privateKey, certPEM)
}

func newCADetails(privateKey *rsa.PrivateKey, certPEM []byte) (*CADetails, error) {
	pubPEM, err := RSAPublicKey2Pem(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := PemToCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	return &CADetails{
		Key:           privateKey,
		Cert:          cert,
		PrivateKeyPEM: RSAPrivateKey2Pem(privateKey),
		PublicKeyPEM:  pubPEM,
		CertPEM:       certPEM,
	}, nil
}

// SaveCADetails writes the CA private key, its matching public key, and the
// certificate PEM. The public key path is keyPath with a .pub extension.
func SaveCADetails(material *CADetails, keyPath, certPath string) error {
	if err := SaveRSAPrivateKey(material.Key, keyPath); err != nil {
		return err
	}
	if err := SaveRSAPublicKey(&material.Key.PublicKey, publicKeyFilename(keyPath)); err != nil {
		return err
	}
	return SaveCertificate(material.CertPEM, certPath)
}

// LoadCertificate reads a PEM certificate from path.
func LoadCertificate(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return PemToCertificate(certBytes)
}

// PemToCertificate parses the first PEM block in pemBytes as an X.509 certificate.
func PemToCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// CreateSelfSignedCertificate returns a PEM-encoded self-signed CA certificate
// for commonName, valid from notBefore until notAfter. dnsNames may be nil.
func CreateSelfSignedCertificate(privateKey *rsa.PrivateKey, commonName string, dnsNames []string, notBefore, notAfter time.Time) ([]byte, error) {
	return createSelfSignedCertificate(privateKey, govWifiOrganization, commonName, dnsNames, notBefore, notAfter)
}

func createSelfSignedCertificate(privateKey *rsa.PrivateKey, organization, commonName string, dnsNames []string, notBefore, notAfter time.Time) ([]byte, error) {
	template, err := newCATemplate(organization, commonName, notBefore, notAfter, 1)
	if err != nil {
		return nil, err
	}
	template.DNSNames = dnsNames

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	return encodeCertificatePEM(certDER), nil
}

// CreateIntermediateCertificate returns a PEM-encoded intermediate CA certificate
// for commonName, signed by rootCert with rootKey and valid from notBefore until notAfter.
func CreateIntermediateCertificate(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, intermediateKey *rsa.PrivateKey, commonName string, notBefore, notAfter time.Time) ([]byte, error) {
	return createIntermediateCertificate(rootCert, rootKey, intermediateKey, govWifiOrganization, commonName, notBefore, notAfter)
}

func createIntermediateCertificate(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, intermediateKey *rsa.PrivateKey, organization, commonName string, notBefore, notAfter time.Time) ([]byte, error) {
	template, err := newCATemplate(organization, commonName, notBefore, notAfter, 0)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	return encodeCertificatePEM(certDER), nil
}

func newCATemplate(organization, commonName string, notBefore, notAfter time.Time, maxPathLen int) (*x509.Certificate, error) {
	return newCATemplateWindow(organization, commonName, notBefore, notAfter, maxPathLen)
}

func newCATemplateUntil(commonName string, notAfter time.Time, maxPathLen int) (*x509.Certificate, error) {
	if notAfter.IsZero() {
		return nil, errors.New("expiry date is required")
	}
	notBefore, notAfter := validityWindow(notAfter)
	return newCATemplateWindow(govWifiOrganization, commonName, notBefore, notAfter, maxPathLen)
}

// validityWindow keeps NotBefore before NotAfter. A future expiry starts now.
// An expiry that has already passed is a 10-year window ending at notAfter,
// so the certificate is well-formed and already expired.
func validityWindow(notAfter time.Time) (time.Time, time.Time) {
	notAfter = notAfter.UTC()
	now := time.Now().UTC()
	if notAfter.After(now) {
		return now, notAfter
	}
	return notAfter.AddDate(-10, 0, 0), notAfter
}

func newCATemplateWindow(organization, commonName string, notBefore, notAfter time.Time, maxPathLen int) (*x509.Certificate, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}
	if organization == "" {
		organization = govWifiOrganization
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{govWifiCountry},
			Organization: []string{organization},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            maxPathLen,
		MaxPathLenZero:        maxPathLen == 0,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}, nil
}

func newSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func encodeCertificatePEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// SaveCertificate writes certPEM to filename, replacing any existing file.
func SaveCertificate(certPEM []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(certPEM)
	return err
}
