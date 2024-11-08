// Adapted from the Go standard library generate_cert.go
// Source: https://github.com/golang/go/blob/master/src/crypto/tls/generate_cert.go

// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

package testutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type certFlags struct {
	// Comma-separated hostnames and IPs to generate a certificate for
	host *string

	//Creation date formatted as Jan 1 15:04:05 2011
	validFrom *string

	// Duration that certificate is valid for
	validFor *time.Duration

	// Whether this cert should be its own Certificate Authority
	isCA *bool

	// Size of RSA key to generate. Ignored if ecdsaCurve is set
	rsaBits *int

	// ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521
	ecdsaCurve *string

	// Generate an Ed25519 key
	ed25519Key *bool
}

func generateCert(certFlags certFlags, certPath, keyPath string) error {
	setDefaults(&certFlags)

	if len(*certFlags.host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	var priv any
	var err error
	switch *certFlags.ecdsaCurve {
	case "":
		if *certFlags.ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			priv, err = rsa.GenerateKey(rand.Reader, *certFlags.rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized elliptic curve: %q", *certFlags.ecdsaCurve)
	}
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(*certFlags.validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *certFlags.validFrom)
		if err != nil {
			return fmt.Errorf("failed to parse creation date: %v", err)
		}
	}

	notAfter := notBefore.Add(*certFlags.validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*certFlags.host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *certFlags.isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	certOut, err := os.Create(filepath.Clean(certPath))
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing cert.pem: %v", err)
	}

	keyOut, err := os.OpenFile(filepath.Clean(keyPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing key.pem: %v", err)
	}
	return nil
}

func setDefaults(certFlags *certFlags) {
	if certFlags.host == nil {
		certFlags.host = new(string)
		*certFlags.host = ""
	}

	if certFlags.validFrom == nil {
		certFlags.validFrom = new(string)
		*certFlags.validFrom = ""
	}

	if certFlags.validFor == nil {
		certFlags.validFor = new(time.Duration)
		*certFlags.validFor = 365 * 24 * time.Hour
	}

	if certFlags.isCA == nil {
		certFlags.isCA = new(bool)
		*certFlags.isCA = false
	}

	if certFlags.rsaBits == nil {
		certFlags.rsaBits = new(int)
		*certFlags.rsaBits = 2048
	}

	if certFlags.ecdsaCurve == nil {
		certFlags.ecdsaCurve = new(string)
		*certFlags.ecdsaCurve = ""
	}

	if certFlags.ed25519Key == nil {
		certFlags.ed25519Key = new(bool)
		*certFlags.ed25519Key = false
	}
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
