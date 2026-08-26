package pki

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"
)

// CertificateText returns a human-readable certificate dump similar to
// `openssl x509 -noout -text`.
func CertificateText(cert *x509.Certificate) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Certificate:\n")
	fmt.Fprintf(&b, "    Data:\n")
	fmt.Fprintf(&b, "        Version: %d (0x%x)\n", cert.Version, cert.Version-1)
	fmt.Fprintf(&b, "        Serial Number:\n")
	fmt.Fprintf(&b, "            %s\n", formatSerial(cert))
	fmt.Fprintf(&b, "        Signature Algorithm: %s\n", signatureAlgorithmName(cert.SignatureAlgorithm))
	fmt.Fprintf(&b, "        Issuer: %s\n", formatName(cert.Issuer))
	fmt.Fprintf(&b, "        Validity\n")
	fmt.Fprintf(&b, "            Not Before: %s\n", formatTime(cert.NotBefore))
	fmt.Fprintf(&b, "            Not After : %s\n", formatTime(cert.NotAfter))
	fmt.Fprintf(&b, "        Subject: %s\n", formatName(cert.Subject))
	fmt.Fprintf(&b, "        Subject Public Key Info:\n")
	fmt.Fprintf(&b, "            Public Key Algorithm: %s\n", publicKeyAlgorithmName(cert.PublicKeyAlgorithm))
	writePublicKeyInfo(&b, cert)
	fmt.Fprintf(&b, "        X509v3 extensions:\n")
	writeExtensions(&b, cert)
	fmt.Fprintf(&b, "    Signature Algorithm: %s\n", signatureAlgorithmName(cert.SignatureAlgorithm))
	writeHexDump(&b, cert.Signature, "         ")

	return b.String()
}

func formatSerial(cert *x509.Certificate) string {
	serial := strings.ToUpper(cert.SerialNumber.Text(16))
	if len(serial)%2 == 1 {
		serial = "0" + serial
	}
	var parts []string
	for i := 0; i < len(serial); i += 2 {
		parts = append(parts, serial[i:i+2])
	}
	return strings.Join(parts, ":")
}

func formatName(name pkix.Name) string {
	var parts []string
	for _, c := range name.Country {
		parts = append(parts, "C = "+c)
	}
	for _, o := range name.Organization {
		parts = append(parts, "O = "+o)
	}
	for _, ou := range name.OrganizationalUnit {
		parts = append(parts, "OU = "+ou)
	}
	if name.CommonName != "" {
		parts = append(parts, "CN = "+name.CommonName)
	}
	return strings.Join(parts, ", ")
}

func formatTime(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006 GMT")
}

func signatureAlgorithmName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.SHA256WithRSA:
		return "sha256WithRSAEncryption"
	case x509.SHA384WithRSA:
		return "sha384WithRSAEncryption"
	case x509.SHA512WithRSA:
		return "sha512WithRSAEncryption"
	default:
		return alg.String()
	}
}

func publicKeyAlgorithmName(alg x509.PublicKeyAlgorithm) string {
	switch alg {
	case x509.RSA:
		return "rsaEncryption"
	default:
		return alg.String()
	}
}

func writePublicKeyInfo(b *strings.Builder, cert *x509.Certificate) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		fmt.Fprintf(b, "                Public-Key: (%d bit)\n", pub.N.BitLen())
		fmt.Fprintf(b, "                Modulus:\n")
		writeHexDump(b, pub.N.Bytes(), "                    ")
		fmt.Fprintf(b, "                Exponent: %d (0x%x)\n", pub.E, pub.E)
	default:
		fmt.Fprintf(b, "                (unsupported public key type)\n")
	}
}

func writeExtensions(b *strings.Builder, cert *x509.Certificate) {
	if cert.KeyUsage != 0 {
		fmt.Fprintf(b, "            X509v3 Key Usage: critical\n")
		fmt.Fprintf(b, "                %s\n", strings.Join(keyUsageNames(cert.KeyUsage), ", "))
	}
	if cert.BasicConstraintsValid {
		fmt.Fprintf(b, "            X509v3 Basic Constraints: critical\n")
		ca := "FALSE"
		if cert.IsCA {
			ca = "TRUE"
		}
		if cert.MaxPathLenZero || cert.MaxPathLen > 0 {
			fmt.Fprintf(b, "                CA:%s, pathlen:%d\n", ca, cert.MaxPathLen)
		} else {
			fmt.Fprintf(b, "                CA:%s\n", ca)
		}
	}
	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(b, "            X509v3 Subject Alternative Name:\n")
		fmt.Fprintf(b, "                %s\n", strings.Join(prefixEach(cert.DNSNames, "DNS:"), ", "))
	}
}

func keyUsageNames(usage x509.KeyUsage) []string {
	var names []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		names = append(names, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		names = append(names, "Non Repudiation")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		names = append(names, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		names = append(names, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		names = append(names, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		names = append(names, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		names = append(names, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		names = append(names, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		names = append(names, "Decipher Only")
	}
	return names
}

func prefixEach(values []string, prefix string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = prefix + v
	}
	return out
}

func writeHexDump(b *strings.Builder, data []byte, indent string) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		var parts []string
		for _, by := range data[i:end] {
			parts = append(parts, fmt.Sprintf("%02x", by))
		}
		line := strings.Join(parts, ":")
		if end < len(data) {
			fmt.Fprintf(b, "%s%s:\n", indent, line)
		} else {
			fmt.Fprintf(b, "%s%s\n", indent, line)
		}
	}
}
