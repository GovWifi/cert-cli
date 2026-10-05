package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

var (
	testNotBefore = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	testNotAfter  = time.Date(2027, 10, 1, 23, 59, 59, 0, time.UTC)
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
