package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"certcli/pki"
)

type pemBundle struct {
	Cert       string `json:"cert"`
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	CommonName string `json:"commonName,omitempty"`
}

type genAllResponse struct {
	Root         pemBundle `json:"root"`
	Intermediate pemBundle `json:"intermediate"`
}

type genChainRequest struct {
	Leaves int `json:"leaves"`
}

type genChainResponse struct {
	Root         pemBundle   `json:"root"`
	Intermediate pemBundle   `json:"intermediate"`
	Leaves       []pemBundle `json:"leaves"`
}

type genExpiryRequest struct {
	Start  string `json:"start"`
	Expiry string `json:"expiry"`
}

type genInterRequest struct {
	RootCert string `json:"rootCert"`
	RootKey  string `json:"rootKey"`
	Start    string `json:"start"`
	Expiry   string `json:"expiry"`
}

type validateRequest struct {
	Cert string `json:"cert"`
	Root string `json:"root"`
}

type validateResponse struct {
	OK          bool   `json:"ok"`
	Message     string `json:"message"`
	Certificate string `json:"certificate"`
	Issuer      string `json:"issuer"`
}

type saveRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type statusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func handleGenRoot(w http.ResponseWriter, r *http.Request) {
	var req genExpiryRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	notBefore, err := pki.ParseDate(req.Start, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	notAfter, err := pki.ResolveExpiryDate(req.Expiry, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	material, err := pki.CreateRootCA(notBefore, notAfter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, bundleFrom(material))
}

func handleGenAll(w http.ResponseWriter, r *http.Request) {
	root, err := pki.CreateRootCA(time.Now(), pki.RootExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	inter, err := pki.CreateIntermediateCA(root.Cert, root.Key, time.Now(), pki.IntermediateExpiry)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, genAllResponse{
		Root:         bundleFrom(root),
		Intermediate: bundleFrom(inter),
	})
}

func handleGenChain(w http.ResponseWriter, r *http.Request) {
	var req genChainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Leaves < 1 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("leaves must be at least 1"))
		return
	}
	if req.Leaves > pki.MaxLeafCount {
		writeError(w, http.StatusBadRequest, fmt.Errorf("leaves must be at most %d", pki.MaxLeafCount))
		return
	}

	chain, err := pki.CreateChain(req.Leaves, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	leaves := make([]pemBundle, 0, len(chain.Leaves))
	for _, leaf := range chain.Leaves {
		leaves = append(leaves, bundleFromNamed(leaf))
	}

	writeJSON(w, http.StatusOK, genChainResponse{
		Root:         bundleFrom(chain.Root),
		Intermediate: bundleFrom(chain.Intermediate),
		Leaves:       leaves,
	})
}

func handleGenInter(w http.ResponseWriter, r *http.Request) {
	var req genInterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.RootCert) == "" || strings.TrimSpace(req.RootKey) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("rootCert and rootKey are required"))
		return
	}

	rootCert, err := pki.PemToCertificate([]byte(req.RootCert))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid root certificate: %w", err))
		return
	}
	rootKey, err := pki.PemToRSAPrivateKey([]byte(req.RootKey))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid root private key: %w", err))
		return
	}
	notBefore, err := pki.ParseDate(req.Start, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	notAfter, err := pki.ResolveExpiryDate(req.Expiry, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	material, err := pki.CreateIntermediateCA(rootCert, rootKey, notBefore, notAfter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, bundleFrom(material))
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.Cert) == "" || strings.TrimSpace(req.Root) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("cert and root are required"))
		return
	}

	cert, err := pki.PemToCertificate([]byte(req.Cert))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid certificate: %w", err))
		return
	}
	root, err := pki.PemToCertificate([]byte(req.Root))
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid root certificate: %w", err))
		return
	}

	resp := validateResponse{
		Certificate: pki.CertificateText(cert),
		Issuer:      pki.CertificateText(root),
	}

	if err := pki.CheckSignedBy(cert, root); err != nil {
		resp.OK = false
		resp.Message = fmt.Sprintf("certificate is not signed by the given root: %v", err)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.OK = true
	resp.Message = "certificate is signed by the given root"
	writeJSON(w, http.StatusOK, resp)
}

func handleSave(w http.ResponseWriter, r *http.Request) {
	var req saveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	path := strings.TrimSpace(req.Path)
	if path == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("path is required"))
		return
	}
	if filepath.IsAbs(path) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("absolute paths are not allowed"))
		return
	}
	clean := filepath.Clean(path)
	if clean == "." || strings.HasPrefix(clean, "..") {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid path"))
		return
	}

	if dir := filepath.Dir(clean); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}

	if err := os.WriteFile(clean, []byte(req.Content), 0o600); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, statusResponse{
		Status:  "ok",
		Message: fmt.Sprintf("wrote %s", clean),
	})
}

func decodeOptionalJSON(r *http.Request, dest any) error {
	if r.Body == nil {
		return nil
	}
	err := json.NewDecoder(r.Body).Decode(dest)
	if err == io.EOF {
		return nil
	}
	return err
}

func bundleFrom(material *pki.CADetails) pemBundle {
	return pemBundle{
		Cert:       string(material.CertPEM),
		PrivateKey: string(material.PrivateKeyPEM),
		PublicKey:  string(material.PublicKeyPEM),
	}
}

func bundleFromNamed(material *pki.CADetails) pemBundle {
	bundle := bundleFrom(material)
	bundle.CommonName = material.Cert.Subject.CommonName
	return bundle
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, statusResponse{
		Status:  "error",
		Message: err.Error(),
	})
}
