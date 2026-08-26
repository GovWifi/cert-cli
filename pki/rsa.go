package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const rsaKeyBits = 4096

func LoadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return PemToRSAPrivateKey(keyBytes)
}

func PemToRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM block is not an RSA private key")
	}
	return privateKey, nil
}

func GetRSAPrivateKey(filename string) (*rsa.PrivateKey, error) {
	privateKey, err := LoadRSAPrivateKey(filename)
	if err != nil {
		privateKey, err = GenerateRSAPrivateKey()
		if err != nil {
			return nil, err
		}

		err = SaveRSAPrivateKey(privateKey, filename)
		if err != nil {
			return nil, err
		}
	}

	if err = SaveRSAPublicKey(&privateKey.PublicKey, publicKeyFilename(filename)); err != nil {
		return nil, err
	}

	return privateKey, nil
}

func GenerateRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeyBits)
}

func SaveRSAPrivateKey(privateKey *rsa.PrivateKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

func RSAPrivateKey2Pem(privateKey *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
}

func RSAPublicKey2Pem(publicKey *rsa.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), nil
}

func SaveRSAPublicKey(publicKey *rsa.PublicKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	pubPEM, err := RSAPublicKey2Pem(publicKey)
	if err != nil {
		return err
	}

	_, err = file.Write(pubPEM)
	return err
}

func GetRSAPublicKey(privateKey *rsa.PrivateKey, filename string) ([]byte, error) {
	pubPEM, err := os.ReadFile(filename)
	if err != nil {
		pubPEM, err = RSAPublicKey2Pem(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}

		if err = SaveRSAPublicKey(&privateKey.PublicKey, filename); err != nil {
			return nil, err
		}
	}

	return pubPEM, nil
}

func publicKeyFilename(privateKeyFilename string) string {
	ext := filepath.Ext(privateKeyFilename)
	return strings.TrimSuffix(privateKeyFilename, ext) + ".pub"
}
