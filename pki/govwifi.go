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
)

var (
	RootValidFor         = 10 * 365 * 24 * time.Hour
	IntermediateValidFor = 5 * 365 * 24 * time.Hour
)

// CADetails is an in-memory CA key pair and certificate.
type CADetails struct {
	Key           *rsa.PrivateKey
	Cert          *x509.Certificate
	PrivateKeyPEM []byte
	PublicKeyPEM  []byte
	CertPEM       []byte
}

func CreateRootCA() (*CADetails, error) {
	privateKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	certPEM, err := CreateSelfSignedCertificate(privateKey, RootCN, nil, RootValidFor)
	if err != nil {
		return nil, err
	}

	return newCADetails(privateKey, certPEM)
}

func CreateIntermediateCA(rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*CADetails, error) {
	privateKey, err := GenerateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	certPEM, err := CreateIntermediateCertificate(rootCert, rootKey, privateKey, IntermediateCN, IntermediateValidFor)
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

func SaveCADetails(material *CADetails, keyPath, certPath string) error {
	if err := SaveRSAPrivateKey(material.Key, keyPath); err != nil {
		return err
	}
	if err := SaveRSAPublicKey(&material.Key.PublicKey, publicKeyFilename(keyPath)); err != nil {
		return err
	}
	return SaveCertificate(material.CertPEM, certPath)
}

func LoadCertificate(path string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return PemToCertificate(certBytes)
}

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

func GetSelfSignedCertificate(keyFilename, certFilename, commonName string, dnsNames []string, validFor time.Duration) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := GetRSAPrivateKey(keyFilename)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(certFilename)
	if err != nil {
		certPEM, err = CreateSelfSignedCertificate(privateKey, commonName, dnsNames, validFor)
		if err != nil {
			return nil, nil, err
		}

		if err = SaveCertificate(certPEM, certFilename); err != nil {
			return nil, nil, err
		}
	}

	return privateKey, certPEM, nil
}

func GetIntermediateCertificate(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, keyFilename, certFilename, commonName string, validFor time.Duration) (*rsa.PrivateKey, []byte, error) {
	privateKey, err := GetRSAPrivateKey(keyFilename)
	if err != nil {
		return nil, nil, err
	}

	certPEM, err := os.ReadFile(certFilename)
	if err != nil {
		certPEM, err = CreateIntermediateCertificate(rootCert, rootKey, privateKey, commonName, validFor)
		if err != nil {
			return nil, nil, err
		}

		if err = SaveCertificate(certPEM, certFilename); err != nil {
			return nil, nil, err
		}
	}

	return privateKey, certPEM, nil
}

func CreateSelfSignedCertificate(privateKey *rsa.PrivateKey, commonName string, dnsNames []string, validFor time.Duration) ([]byte, error) {
	template, err := newCATemplate(commonName, validFor, 1)
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

func CreateIntermediateCertificate(rootCert *x509.Certificate, rootKey *rsa.PrivateKey, intermediateKey *rsa.PrivateKey, commonName string, validFor time.Duration) ([]byte, error) {
	template, err := newCATemplate(commonName, validFor, 0)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &intermediateKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}

	return encodeCertificatePEM(certDER), nil
}

func newCATemplate(commonName string, validFor time.Duration, maxPathLen int) (*x509.Certificate, error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{govWifiCountry},
			Organization: []string{govWifiOrganization},
			CommonName:   commonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
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

func SaveCertificate(certPEM []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(certPEM)
	return err
}

func Certificate2Pem(cert *x509.Certificate) []byte {
	return encodeCertificatePEM(cert.Raw)
}
