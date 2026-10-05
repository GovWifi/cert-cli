package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRSAPrivateKey(t *testing.T) {
	key, err := GenerateRSAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 4096 {
		t.Fatalf("key size = %d, want 4096", key.N.BitLen())
	}
	if key.E == 0 {
		t.Fatal("expected a public exponent")
	}
}

func TestRSAPrivateKeyPEMRoundTrip(t *testing.T) {
	key := testRSAKey(t)
	pemBytes := RSAPrivateKey2Pem(key)
	if !bytes.Contains(pemBytes, []byte("BEGIN RSA PRIVATE KEY")) {
		t.Fatalf("PEM = %s", pemBytes)
	}

	got, err := PemToRSAPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatal("parsed key does not match")
	}
}

func TestPemToRSAPrivateKeyPKCS8(t *testing.T) {
	key := testRSAKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := PemToRSAPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Fatal("parsed PKCS#8 key does not match")
	}
}

func TestPemToRSAPrivateKeyRejectsInvalid(t *testing.T) {
	if _, err := PemToRSAPrivateKey(nil); err == nil || !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Fatalf("empty input error = %v", err)
	}
	if _, err := PemToRSAPrivateKey([]byte("not a pem")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}

	bad := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not-a-key")})
	if _, err := PemToRSAPrivateKey(bad); err == nil {
		t.Fatal("expected error for a corrupt key")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	_, err = PemToRSAPrivateKey(ecPEM)
	if err == nil || !strings.Contains(err.Error(), "not an RSA private key") {
		t.Fatalf("error = %v", err)
	}
}

func TestRSAPublicKey2Pem(t *testing.T) {
	key := testRSAKey(t)
	pemBytes, err := RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pemBytes, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("PEM = %s", pemBytes)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 {
		t.Fatal("parsed public key does not match")
	}
}

func TestSaveAndLoadRSAKeys(t *testing.T) {
	key := testRSAKey(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	pubPath := filepath.Join(dir, "key.pub")

	if err := SaveRSAPrivateKey(key, keyPath); err != nil {
		t.Fatal(err)
	}
	if err := SaveRSAPublicKey(&key.PublicKey, pubPath); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadRSAPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("loaded private key does not match")
	}

	if _, err := LoadRSAPrivateKey(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for a missing key")
	}
	if err := SaveRSAPrivateKey(key, dir); err == nil {
		t.Fatal("expected error when the private key path is a directory")
	}
	if err := SaveRSAPublicKey(&key.PublicKey, dir); err == nil {
		t.Fatal("expected error when the public key path is a directory")
	}
}

func TestGetRSAPrivateKey(t *testing.T) {
	key := testRSAKey(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.pem")
	pubPath := strings.TrimSuffix(path, ".pem") + ".pub"
	if err := SaveRSAPrivateKey(key, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := GetRSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Fatal("loaded an unexpected key")
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, wantPub) {
		t.Fatal("public key was not rewritten from the private key")
	}
}

func TestGetRSAPrivateKeyGeneratesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-key.pem")
	key, err := GetRSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 4096 {
		t.Fatalf("key size = %d, want 4096", key.N.BitLen())
	}

	loaded, err := LoadRSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.N.Cmp(key.N) != 0 {
		t.Fatal("saved key does not match the returned key")
	}
	pub, err := os.ReadFile(strings.TrimSuffix(path, ".pem") + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	wantPub, err := RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, wantPub) {
		t.Fatal("generated public key does not match")
	}
}

func TestGetRSAPublicKey(t *testing.T) {
	key := testRSAKey(t)
	dir := t.TempDir()

	missing := filepath.Join(dir, "missing.pub")
	got, err := GetRSAPublicKey(key, missing)
	if err != nil {
		t.Fatal(err)
	}
	want, err := RSAPublicKey2Pem(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("derived public key does not match")
	}
	onDisk, err := os.ReadFile(missing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, want) {
		t.Fatal("public key was not saved")
	}

	existing := filepath.Join(dir, "existing.pub")
	mustWrite(t, existing, []byte("keep"))
	got, err = GetRSAPublicKey(key, existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("keep")) {
		t.Fatalf("got %q", got)
	}
	onDisk, err = os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, []byte("keep")) {
		t.Fatal("existing public key file was rewritten")
	}
}
