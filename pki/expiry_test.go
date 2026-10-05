package pki

import (
	"testing"
	"time"
)

func TestDefaultExpiryIsTenYearsFromToday(t *testing.T) {
	loc := time.FixedZone("UTC+1", 60*60)
	now := time.Date(2026, 10, 1, 9, 37, 0, 0, loc)
	got := DefaultExpiry(now)
	want := time.Date(2036, 10, 1, 23, 59, 59, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseDateAllowsPastDates(t *testing.T) {
	loc := time.FixedZone("UTC+1", 60*60)
	now := time.Date(2026, 10, 1, 9, 37, 0, 0, loc)
	got, err := ParseDate("2020-01-15", now)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2020, 1, 15, 23, 59, 59, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
	if !got.Before(now) {
		t.Fatal("expected a past expiry")
	}
}

func TestParseDateRejectsInvalid(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, value := range []string{"next-year", "01-10-2026", "2026-13-01", "2026-02-31"} {
		if _, err := ParseDate(value, now); err == nil {
			t.Fatalf("expected error for %q", value)
		}
	}
}

func TestResolveExpiryDateEmptyUsesDefault(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	got, err := ResolveExpiryDate("  ", now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(DefaultExpiry(now)) {
		t.Fatalf("got %s, want %s", got, DefaultExpiry(now))
	}
}

func TestNewCATemplateUntilFutureStartsNow(t *testing.T) {
	notAfter := time.Now().UTC().AddDate(10, 0, 0)
	before := time.Now().UTC()
	tmpl, err := newCATemplateUntil(RootCN, notAfter, 1)
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.NotBefore.Before(before.Add(-time.Second)) || tmpl.NotBefore.After(after.Add(time.Second)) {
		t.Fatalf("NotBefore = %s, want approximately now", tmpl.NotBefore)
	}
	if !tmpl.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %s, want %s", tmpl.NotAfter, notAfter)
	}
}

func TestNewCATemplateUntilExpired(t *testing.T) {
	notAfter := time.Date(2020, 1, 15, 23, 59, 59, 0, time.UTC)
	tmpl, err := newCATemplateUntil(IntermediateCN, notAfter, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !tmpl.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter = %s, want %s", tmpl.NotAfter, notAfter)
	}
	wantBefore := notAfter.AddDate(-10, 0, 0)
	if !tmpl.NotBefore.Equal(wantBefore) {
		t.Fatalf("NotBefore = %s, want %s", tmpl.NotBefore, wantBefore)
	}
	if !tmpl.NotBefore.Before(tmpl.NotAfter) {
		t.Fatal("NotBefore must be before NotAfter")
	}
	if !tmpl.MaxPathLenZero {
		t.Fatal("expected intermediate max path length of zero")
	}
}

func TestCreateCertificatesAllowsExpiredWindow(t *testing.T) {
	rootKey := testRSAKey(t)
	notAfter := time.Now().AddDate(-1, 0, 0).UTC()
	notBefore := notAfter.AddDate(-1, 0, 0)

	rootPEM, err := CreateSelfSignedCertificate(rootKey, RootCN, nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !rootCert.NotAfter.Before(time.Now()) {
		t.Fatal("expected an expired root certificate")
	}

	interKey := testRSAKey(t)
	interPEM, err := CreateIntermediateCertificate(rootCert, rootKey, interKey, IntermediateCN, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := PemToCertificate(interPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !interCert.NotAfter.Before(time.Now()) {
		t.Fatal("expected an expired intermediate certificate")
	}
	if err := CheckSignedBy(interCert, rootCert); err != nil {
		t.Fatal(err)
	}
}

func TestParseDateTrimsSpace(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	got, err := ParseDate("  2024-06-01  ", now)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2024, 6, 1, 23, 59, 59, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestResolveExpiryDateParsesValue(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	got, err := ResolveExpiryDate("2030-05-04", now)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseDate("2030-05-04", now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestResolveExpiryDateRejectsInvalid(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := ResolveExpiryDate("nope", now); err == nil {
		t.Fatal("expected error")
	}
}
