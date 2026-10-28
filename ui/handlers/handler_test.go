package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"certcli/pki"
)

func TestNewServesStaticFiles(t *testing.T) {
	h := New(fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<h1>cert-cli</h1>")},
		"app.js":     &fstest.MapFile{Data: []byte("console.log('ok')")},
	})

	rec := serve(h, http.MethodGet, "/", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<h1>cert-cli</h1>") {
		t.Fatalf("index status %d body %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content type = %q", ct)
	}

	rec = serve(h, http.MethodGet, "/static/app.js", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "console.log") {
		t.Fatalf("script status %d body %s", rec.Code, rec.Body)
	}

	rec = serve(h, http.MethodGet, "/static/missing.js", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}

	rec = serve(h, http.MethodPost, "/", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestNewMissingIndex(t *testing.T) {
	h := New(fstest.MapFS{})
	rec := serve(h, http.MethodGet, "/", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestAPIGenRoot(t *testing.T) {
	h := New(fstest.MapFS{})

	rec := serve(h, http.MethodPost, "/api/gen/root", strings.NewReader(""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body status = %d, body = %s", rec.Code, rec.Body)
	}

	rec = postJSON(t, h, "/api/gen/root", map[string]string{"start": "yesterday"})
	assertError(t, rec, http.StatusBadRequest, "YYYY-MM-DD")

	rec = postJSON(t, h, "/api/gen/root", map[string]string{"start": "2026-10-01", "expiry": "not-a-date"})
	assertError(t, rec, http.StatusBadRequest, "YYYY-MM-DD")

	rec = postJSON(t, h, "/api/gen/root", map[string]string{"start": "2026-10-01", "expiry": "2027-10-01"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	bundle := decodeBundle(t, rec.Body.Bytes())
	cert, err := pki.PemToCertificate([]byte(bundle.Cert))
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != pki.RootCN {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if err := pki.CheckSignedBy(cert, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.PemToRSAPrivateKey([]byte(bundle.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(bundle.PublicKey, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key = %s", bundle.PublicKey)
	}
}

func TestAPIGenInter(t *testing.T) {
	h := New(fstest.MapFS{})
	rootKey := mustKey(t)
	rootPEM, err := pki.CreateSelfSignedCertificate(rootKey, "root", nil, mustDate(t, "2026-10-01"), mustDate(t, "2028-10-01"))
	if err != nil {
		t.Fatal(err)
	}
	rootKeyPEM := pki.RSAPrivateKey2Pem(rootKey)

	rec := postJSON(t, h, "/api/gen/inter", map[string]string{})
	assertError(t, rec, http.StatusBadRequest, "rootCert and rootKey are required")

	rec = postJSON(t, h, "/api/gen/inter", map[string]string{
		"rootCert": "nope",
		"rootKey":  string(rootKeyPEM),
		"start":    "2026-10-01",
	})
	assertError(t, rec, http.StatusBadRequest, "invalid root certificate")

	rec = postJSON(t, h, "/api/gen/inter", map[string]string{
		"rootCert": string(rootPEM),
		"rootKey":  "nope",
		"start":    "2026-10-01",
	})
	assertError(t, rec, http.StatusBadRequest, "invalid root private key")

	rec = postJSON(t, h, "/api/gen/inter", map[string]string{
		"rootCert": string(rootPEM),
		"rootKey":  string(rootKeyPEM),
		"start":    "bad",
	})
	assertError(t, rec, http.StatusBadRequest, "YYYY-MM-DD")

	rec = postJSON(t, h, "/api/gen/inter", map[string]string{
		"rootCert": string(rootPEM),
		"rootKey":  string(rootKeyPEM),
		"start":    "2026-10-01",
		"expiry":   "2027-10-01",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	bundle := decodeBundle(t, rec.Body.Bytes())
	cert, err := pki.PemToCertificate([]byte(bundle.Cert))
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pki.PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != pki.IntermediateCN {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if err := pki.CheckSignedBy(cert, rootCert); err != nil {
		t.Fatal(err)
	}
}

func TestAPIGenLeaf(t *testing.T) {
	h := New(fstest.MapFS{})
	rootKey := mustKey(t)
	notBefore := mustDate(t, "2026-10-01")
	notAfter := mustDate(t, "2028-10-01")
	rootPEM, err := pki.CreateSelfSignedCertificate(rootKey, "root", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pki.PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	interKey := mustKey(t)
	interPEM, err := pki.CreateIntermediateCertificate(rootCert, rootKey, interKey, "inter", notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	interKeyPEM := pki.RSAPrivateKey2Pem(interKey)

	rec := postJSON(t, h, "/api/gen/leaf", map[string]string{})
	assertError(t, rec, http.StatusBadRequest, "intermediateCert and intermediateKey are required")

	rec = postJSON(t, h, "/api/gen/leaf", map[string]string{
		"intermediateCert": "nope",
		"intermediateKey":  string(interKeyPEM),
		"start":            "2026-10-01",
	})
	assertError(t, rec, http.StatusBadRequest, "invalid intermediate certificate")

	rec = postJSON(t, h, "/api/gen/leaf", map[string]string{
		"intermediateCert": string(interPEM),
		"intermediateKey":  "nope",
		"start":            "2026-10-01",
	})
	assertError(t, rec, http.StatusBadRequest, "invalid intermediate private key")

	rec = postJSON(t, h, "/api/gen/leaf", map[string]string{
		"intermediateCert": string(interPEM),
		"intermediateKey":  string(interKeyPEM),
		"start":            "bad",
	})
	assertError(t, rec, http.StatusBadRequest, "YYYY-MM-DD")

	rec = postJSON(t, h, "/api/gen/leaf", map[string]string{
		"intermediateCert": string(interPEM),
		"intermediateKey":  string(interKeyPEM),
		"start":            "2026-10-01",
		"expiry":           "2027-10-01",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	bundle := decodeBundle(t, rec.Body.Bytes())
	cert, err := pki.PemToCertificate([]byte(bundle.Cert))
	if err != nil {
		t.Fatal(err)
	}
	interCert, err := pki.PemToCertificate(interPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != pki.LeafCommonName(1) {
		t.Fatalf("CN = %q", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Fatal("expected an end-entity leaf")
	}
	if err := pki.CheckSignedBy(cert, interCert); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckSignedBy(cert, rootCert); err == nil {
		t.Fatal("expected the leaf to be signed by the intermediate, not the root")
	}
}

func TestAPIGenAll(t *testing.T) {
	h := New(fstest.MapFS{})
	rec := serve(h, http.MethodGet, "/api/gen/all", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}

	rec = serve(h, http.MethodPost, "/api/gen/all", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp struct {
		Root         pemBundle `json:"root"`
		Intermediate pemBundle `json:"intermediate"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	root, err := pki.PemToCertificate([]byte(resp.Root.Cert))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.PemToCertificate([]byte(resp.Intermediate.Cert))
	if err != nil {
		t.Fatal(err)
	}
	if root.Subject.CommonName != pki.RootCN || inter.Subject.CommonName != pki.IntermediateCN {
		t.Fatalf("CNs = %q, %q", root.Subject.CommonName, inter.Subject.CommonName)
	}
	if err := pki.CheckSignedBy(inter, root); err != nil {
		t.Fatal(err)
	}
}

func TestAPIGenChain(t *testing.T) {
	h := New(fstest.MapFS{})

	rec := serve(h, http.MethodGet, "/api/gen/chain", nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}

	rec = serve(h, http.MethodPost, "/api/gen/chain", strings.NewReader("{"))
	assertError(t, rec, http.StatusBadRequest, "")

	rec = postJSON(t, h, "/api/gen/chain", map[string]int{"leaves": 0})
	assertError(t, rec, http.StatusBadRequest, "at least 1")

	rec = postJSON(t, h, "/api/gen/chain", map[string]int{"leaves": pki.MaxLeafCount + 1})
	assertError(t, rec, http.StatusBadRequest, "at most")

	rec = postJSON(t, h, "/api/gen/chain", map[string]int{"leaves": 1})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp genChainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Leaves) != 1 {
		t.Fatalf("leaves = %d", len(resp.Leaves))
	}
	root, err := pki.PemToCertificate([]byte(resp.Root.Cert))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.PemToCertificate([]byte(resp.Intermediate.Cert))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.PemToCertificate([]byte(resp.Leaves[0].Cert))
	if err != nil {
		t.Fatal(err)
	}
	if root.Subject.CommonName != pki.RootCN || inter.Subject.CommonName != pki.IntermediateCN {
		t.Fatalf("CNs = %q, %q", root.Subject.CommonName, inter.Subject.CommonName)
	}
	if resp.Leaves[0].CommonName != pki.LeafCommonName(1) || leaf.Subject.CommonName != pki.LeafCommonName(1) {
		t.Fatalf("leaf CN = %q / %q", resp.Leaves[0].CommonName, leaf.Subject.CommonName)
	}
	if leaf.IsCA {
		t.Fatal("expected an end-entity leaf")
	}
	if err := pki.CheckSignedBy(inter, root); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckSignedBy(leaf, inter); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckSignedBy(leaf, root); err == nil {
		t.Fatal("expected the leaf to be signed by the intermediate, not the root")
	}
	if _, err := pki.PemToRSAPrivateKey([]byte(resp.Leaves[0].PrivateKey)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Leaves[0].PublicKey, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key = %s", resp.Leaves[0].PublicKey)
	}
}

func TestAPIGenTest(t *testing.T) {
	h := New(fstest.MapFS{})

	rec := serve(h, http.MethodPost, "/api/gen/test", strings.NewReader("{"))
	assertError(t, rec, http.StatusBadRequest, "")

	rec = postJSON(t, h, "/api/gen/test", map[string]any{"leaves": 0})
	assertError(t, rec, http.StatusBadRequest, "at least 1")

	rec = postJSON(t, h, "/api/gen/test", map[string]any{
		"leaves":             1,
		"organization":       "Acme",
		"rootCN":             "Acme Root",
		"intermediateCN":     "Acme Intermediate",
		"rootStart":          "2026-01-01",
		"rootExpiry":         "2036-01-01",
		"intermediateStart":  "2026-02-01",
		"intermediateExpiry": "2031-02-01",
		"leafStart":          "2026-03-01",
		"leafExpiry":         "2027-03-01",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp genChainResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	root, err := pki.PemToCertificate([]byte(resp.Root.Cert))
	if err != nil {
		t.Fatal(err)
	}
	inter, err := pki.PemToCertificate([]byte(resp.Intermediate.Cert))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.PemToCertificate([]byte(resp.Leaves[0].Cert))
	if err != nil {
		t.Fatal(err)
	}
	if root.Subject.CommonName != "Acme Root" || inter.Subject.CommonName != "Acme Intermediate" {
		t.Fatalf("CNs = %q, %q", root.Subject.CommonName, inter.Subject.CommonName)
	}
	if len(root.Subject.Organization) != 1 || root.Subject.Organization[0] != "Acme" {
		t.Fatalf("organization = %v", root.Subject.Organization)
	}
	if !root.NotBefore.Equal(mustDate(t, "2026-01-01")) || !root.NotAfter.Equal(mustDate(t, "2036-01-01")) {
		t.Fatalf("root validity %s – %s", root.NotBefore, root.NotAfter)
	}
	if !inter.NotBefore.Equal(mustDate(t, "2026-02-01")) || !inter.NotAfter.Equal(mustDate(t, "2031-02-01")) {
		t.Fatalf("intermediate validity %s – %s", inter.NotBefore, inter.NotAfter)
	}
	if !leaf.NotBefore.Equal(mustDate(t, "2026-03-01")) || !leaf.NotAfter.Equal(mustDate(t, "2027-03-01")) {
		t.Fatalf("leaf validity %s – %s", leaf.NotBefore, leaf.NotAfter)
	}
	if err := pki.CheckSignedBy(inter, root); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckSignedBy(leaf, inter); err != nil {
		t.Fatal(err)
	}
}

func TestAPIValidate(t *testing.T) {
	h := New(fstest.MapFS{})
	rootKey := mustKey(t)
	notBefore := mustDate(t, "2026-10-01")
	notAfter := mustDate(t, "2028-10-01")
	rootPEM, err := pki.CreateSelfSignedCertificate(rootKey, "root", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	otherPEM, err := pki.CreateSelfSignedCertificate(mustKey(t), "other", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := pki.PemToCertificate(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	interPEM, err := pki.CreateIntermediateCertificate(rootCert, rootKey, mustKey(t), "inter", notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}

	rec := serve(h, http.MethodPost, "/api/validate", strings.NewReader("{"))
	assertError(t, rec, http.StatusBadRequest, "")

	rec = postJSON(t, h, "/api/validate", map[string]string{"cert": "", "root": string(rootPEM)})
	assertError(t, rec, http.StatusBadRequest, "cert and root are required")

	rec = postJSON(t, h, "/api/validate", map[string]string{"cert": "nope", "root": string(rootPEM)})
	assertError(t, rec, http.StatusBadRequest, "invalid certificate")

	rec = postJSON(t, h, "/api/validate", map[string]string{"cert": string(interPEM), "root": "nope"})
	assertError(t, rec, http.StatusBadRequest, "invalid root certificate")

	rec = postJSON(t, h, "/api/validate", map[string]string{"cert": string(interPEM), "root": string(otherPEM)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var mismatch validateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &mismatch); err != nil {
		t.Fatal(err)
	}
	if mismatch.OK || !strings.Contains(mismatch.Message, "not signed") {
		t.Fatalf("response = %+v", mismatch)
	}
	if !strings.Contains(mismatch.Certificate, "CN = inter") || !strings.Contains(mismatch.Issuer, "CN = other") {
		t.Fatalf("certificate text missing subjects: %+v", mismatch)
	}

	rec = postJSON(t, h, "/api/validate", map[string]string{"cert": string(interPEM), "root": string(rootPEM)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var okResp validateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &okResp); err != nil {
		t.Fatal(err)
	}
	if !okResp.OK || okResp.Message != "certificate is signed by the given root" {
		t.Fatalf("response = %+v", okResp)
	}
}

func TestAPIView(t *testing.T) {
	h := New(fstest.MapFS{})
	rootKey := mustKey(t)
	notBefore := mustDate(t, "2026-10-01")
	notAfter := mustDate(t, "2028-10-01")
	rootPEM, err := pki.CreateSelfSignedCertificate(rootKey, "root", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}

	rec := serve(h, http.MethodPost, "/api/view", strings.NewReader("{"))
	assertError(t, rec, http.StatusBadRequest, "")

	rec = postJSON(t, h, "/api/view", map[string]string{"cert": ""})
	assertError(t, rec, http.StatusBadRequest, "cert is required")

	rec = postJSON(t, h, "/api/view", map[string]string{"cert": "nope"})
	assertError(t, rec, http.StatusBadRequest, "invalid certificate")

	rec = postJSON(t, h, "/api/view", map[string]string{"cert": string(rootPEM)})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp viewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Certificate, "CN = root") {
		t.Fatalf("certificate text missing subject: %+v", resp)
	}
}

func TestAPISave(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	h := New(fstest.MapFS{})

	rec := serve(h, http.MethodPost, "/api/save", strings.NewReader("{"))
	assertError(t, rec, http.StatusBadRequest, "")

	rec = postJSON(t, h, "/api/save", map[string]string{"content": "pem"})
	assertError(t, rec, http.StatusBadRequest, "path is required")

	rec = postJSON(t, h, "/api/save", map[string]string{"path": "/tmp/cert.pem", "content": "pem"})
	assertError(t, rec, http.StatusBadRequest, "absolute paths are not allowed")

	rec = postJSON(t, h, "/api/save", map[string]string{"path": "../cert.pem", "content": "pem"})
	assertError(t, rec, http.StatusBadRequest, "invalid path")

	rec = postJSON(t, h, "/api/save", map[string]string{"path": ".", "content": "pem"})
	assertError(t, rec, http.StatusBadRequest, "invalid path")

	rec = postJSON(t, h, "/api/save", map[string]string{"path": "nested/dir/cert.pem", "content": "pem-data"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var resp statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != "ok" || !strings.Contains(resp.Message, "nested/dir/cert.pem") {
		t.Fatalf("response = %+v", resp)
	}
	got, err := os.ReadFile(filepath.Join(dir, "nested/dir/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "pem-data" {
		t.Fatalf("got %q", got)
	}
	info, err := os.Stat(filepath.Join(dir, "nested/dir/cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := pki.ParseDate(value, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func postJSON(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatal(err)
	}
	return serve(h, http.MethodPost, path, &buf)
}

func serve(h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBundle(t *testing.T, body []byte) pemBundle {
	t.Helper()
	var bundle pemBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	return bundle
}

func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, status, rec.Body)
	}
	var resp statusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body)
	}
	if resp.Status != "error" {
		t.Fatalf("status field = %q, body = %s", resp.Status, rec.Body)
	}
	if message != "" && !strings.Contains(resp.Message, message) {
		t.Fatalf("message = %q, want substring %q", resp.Message, message)
	}
}
