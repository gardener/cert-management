/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"k8s.io/utils/ptr"
)

// DefaultCertExtKeyUsage are the default Extended KeyUsage (letsencrypt default).
var DefaultCertExtKeyUsage []x509.ExtKeyUsage = []x509.ExtKeyUsage{
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageServerAuth,
}

const (
	// DefaultPubKeyAlgo is the default Public Key Algorithm (letsencrypt default).
	DefaultPubKeyAlgo x509.PublicKeyAlgorithm = x509.RSA
	// DefaultCertKeyUsage is the default Key Usage (letsencrypt default).
	DefaultCertKeyUsage x509.KeyUsage = x509.KeyUsageDigitalSignature

	// RSAKeyUsage is a specific KeyUsage for RSA keys. In the context of TLS,
	// this KeyUsage is particular to RSA key exchange and authentication.
	RSAKeyUsage x509.KeyUsage = x509.KeyUsageKeyEncipherment
	// CAKeyUsage is the KeyUsage required for a Certificate Authority.
	CAKeyUsage x509.KeyUsage = x509.KeyUsageCertSign

	// DefaultCertDuration is the default Certificate validity period (letsencrypt default).
	DefaultCertDuration time.Duration = 24 * time.Hour * 90

	// RSAMinSize is the minimum size for an RSA key
	RSAMinSize int = 2048
	// RSAMaxSize is the maximum size for an RSA key
	RSAMaxSize int = 8192

	// ECCurve256 represents a 256bit ECDSA key.
	ECCurve256 int = 256
	// ECCurve384 represents a 384bit ECDSA key.
	ECCurve384 int = 384
	// ECCurve521 represents a 521bit ECDSA key.
	ECCurve521 int = 521
)

// issueSignedCert does all the Certificate Issuing.
func issueSignedCert(csr *x509.CertificateRequest, isCA bool, privKey crypto.Signer, privKeyPEM []byte, signerKeyPair *TLSKeyPair, duration time.Duration) (*certificate.Resource, error) {
	csrPEM, err := generateCSRPEM(csr, privKey)
	if err != nil {
		return nil, err
	}
	crt, err := generateCertFromCSR(csrPEM, duration, isCA)
	if err != nil {
		return nil, err
	}
	crtPEM, err := signCert(crt, &signerKeyPair.Cert, privKey.Public(), signerKeyPair.Key)
	if err != nil {
		return nil, err
	}
	issuerPEM := bytes.NewBuffer([]byte{})
	err = encodeCertPEM(issuerPEM, signerKeyPair.Cert.Raw)
	if err != nil {
		return nil, err
	}

	return &certificate.Resource{
		PrivateKey:        privKeyPEM,
		Certificate:       crtPEM,
		IssuerCertificate: issuerPEM.Bytes(),
		CSR:               csrPEM,
	}, nil
}

// defaultKeySize returns the default key size based on a public key algorithm.
func defaultKeySize(algo x509.PublicKeyAlgorithm) int {
	if algo == x509.RSA {
		return RSAMinSize
	}
	return ECCurve521
}

// GenerateKey generates a crypto.Signer key and its PEM encoded format.
func GenerateKey(algo x509.PublicKeyAlgorithm, size int) (crypto.Signer, []byte, error) {
	var key crypto.Signer
	var err error

	switch algo {
	case x509.RSA:
		if size < RSAMinSize {
			return nil, nil, fmt.Errorf("RSA key is too weak")
		}
		if size > RSAMaxSize {
			return nil, nil, fmt.Errorf("RSA key size too large")
		}

		key, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate RSA private key: %w", err)
		}
	case x509.ECDSA:
		var curve elliptic.Curve
		switch size {
		case ECCurve521:
			curve = elliptic.P521()
		case ECCurve384:
			curve = elliptic.P384()
		case ECCurve256:
			curve = elliptic.P256()
		default:
			return nil, nil, fmt.Errorf("invalid elliptic curve")
		}

		key, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to generate RSA private key: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("algorithm not supported")
	}

	pem, err := privateKeyToBytes(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding private key failed: %w", err)
	}
	return key, pem, nil
}

// createCertReq creates an x509.CertificateRequest template that can be used
// to generate a PEM encoded CSR.
func createCertReq(input ObtainInput) (*x509.CertificateRequest, error) {
	subjectCA := &input.CAKeyPair.Cert.Subject

	return &x509.CertificateRequest{
		Version:            3,
		PublicKeyAlgorithm: DefaultPubKeyAlgo,
		Subject: pkix.Name{
			CommonName:         ptr.Deref(input.CommonName, ""),
			Country:            subjectCA.Country,
			Organization:       subjectCA.Organization,
			OrganizationalUnit: subjectCA.OrganizationalUnit,
			Locality:           subjectCA.Locality,
			Province:           subjectCA.Province,
			StreetAddress:      subjectCA.StreetAddress,
			PostalCode:         subjectCA.PostalCode,
		},
		DNSNames:       input.DNSNames,
		EmailAddresses: input.CAKeyPair.Cert.EmailAddresses,
	}, nil
}

// generateCSRPEM generates a PEM encoded CSR based on an x509.CertificateRequest and crypto.Signer
func generateCSRPEM(csr *x509.CertificateRequest, privateKey crypto.Signer) ([]byte, error) {
	derBytes, err := x509.CreateCertificateRequest(rand.Reader, csr, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = encodeCSRPEM(pemBytes, derBytes)
	if err != nil {
		return nil, err
	}

	return pemBytes.Bytes(), err
}

// generateCertFromCSR generates an x509.Certificate based on a PEM encoded CSR.
func generateCertFromCSR(csrPEM []byte, duration time.Duration, isCA bool) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	csr, err := extractCertificateRequest(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	ku := DefaultCertKeyUsage
	if csr.PublicKeyAlgorithm == x509.RSA {
		ku |= RSAKeyUsage
	}
	if isCA {
		ku |= CAKeyUsage
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	return &x509.Certificate{
		Version:               csr.Version,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		IsCA:                  isCA,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              ku,
		ExtKeyUsage:           DefaultCertExtKeyUsage,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
	}, nil
}

// newSelfSignedCertInPEMFormat returns a self-signed certificate and the private key in PEM format.
func newSelfSignedCertInPEMFormat(
	input ObtainInput, algo x509.PublicKeyAlgorithm, algoSize int) ([]byte, []byte, error) {
	if input.CommonName == nil {
		return nil, nil, fmt.Errorf("common name must be set")
	}
	if input.Duration == nil {
		return nil, nil, fmt.Errorf("duration must be set")
	}
	certPrivateKey, certPrivateKeyPEM, err := generateKey(algo, algoSize)
	if err != nil {
		return nil, nil, err
	}
	keyUsage := DefaultCertKeyUsage | CAKeyUsage
	if algo == x509.RSA {
		keyUsage |= RSAKeyUsage
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: *input.CommonName,
		},
		DNSNames:              input.DNSNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(*input.Duration),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
	}

	certDerBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, certPrivateKey.Public(), certPrivateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	return certPEM, certPrivateKeyPEM, nil
}

// signCert creates a PEM encoded signed certificate.
func signCert(cert, issuerCert *x509.Certificate, publicKey crypto.PublicKey, signerKey crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.CreateCertificate(rand.Reader, cert, issuerCert, publicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("error creating x509 certificate: %w", err)
	}

	pemBytes := bytes.NewBuffer([]byte{})
	err = encodeCertPEM(pemBytes, derBytes)
	if err != nil {
		return nil, err
	}

	return pemBytes.Bytes(), err
}

// IsCertExpired returns true if a certificate is expired.
func IsCertExpired(crt x509.Certificate) bool {
	return crt.NotAfter.Before(time.Now())
}

// IsCertCA returns true if a certificate is a CA.
func IsCertCA(crt x509.Certificate) bool {
	return crt.IsCA
}

// PublicKeyFromPrivateKey returns the crypto.PublicKey
// for a crypto.PrivateKey or a crypto.Signer.
func PublicKeyFromPrivateKey(key interface{}) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Public(), nil
	case *ecdsa.PrivateKey:
		return k.Public(), nil
	default:
		return nil, fmt.Errorf("unknown private key type: %T", key)
	}
}

// ValidatePublicKeyWithPrivateKey returns true if a crypto.PublicKey matches
// the crypto.PublicKey contained in a crypto.PrivateKey
func ValidatePublicKeyWithPrivateKey(checkPubKey crypto.PublicKey, privKey crypto.PrivateKey) (bool, error) {
	pubKey, err := PublicKeyFromPrivateKey(privKey)
	if err != nil {
		return false, err
	}
	match, err := PublicKeysEqual(pubKey, checkPubKey)
	if err != nil {
		return false, err
	}
	if !match {
		return false, nil
	}
	return true, nil
}

// pubKeySize returns the bit size of a key
func pubKeySize(key interface{}) int {
	if key == nil {
		return 0
	}

	if ecdsaKey, ok := key.(*ecdsa.PublicKey); ok {
		return ecdsaKey.Curve.Params().BitSize
	} else if rsaKey, ok := key.(*rsa.PublicKey); ok {
		return rsaKey.N.BitLen()
	}
	return 0
}

// PublicKeysEqual returns true if two crypto.PublicKey are equal
func PublicKeysEqual(a, b crypto.PublicKey) (bool, error) {
	switch pub := a.(type) {
	case *rsa.PublicKey:
		rsaCheck, ok := b.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.N.Cmp(rsaCheck.N) != 0 {
			return false, nil
		}
		return true, nil
	case *ecdsa.PublicKey:
		ecdsaCheck, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		if pub.X.Cmp(ecdsaCheck.X) != 0 || pub.Y.Cmp(ecdsaCheck.Y) != 0 {
			return false, nil
		}
		return true, nil
	default:
		return false, fmt.Errorf("unrecognised public key type")
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal ECDSA private key: %v", err)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %t", priv)
	}
}

// encodeCSRPEM encodes a Certificate Request in the DER format to PEM.
func encodeCSRPEM(out io.Writer, derBytes []byte) error {
	return encodePEM(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes})
}

// encodeCertPEM encodes a Certificate in the DER format to PEM.
func encodeCertPEM(out io.Writer, derBytes []byte) error {
	return encodePEM(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
}

func encodePEM(out io.Writer, b *pem.Block) error {
	err := pem.Encode(out, b)
	if err != nil {
		return fmt.Errorf("error encoding certificate PEM: %w", err)
	}
	return nil
}

func privateKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	block, err := pemBlockForKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

func bytesToPrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decoding pem block for private key failed")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("incomplete decoding pem block for private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	key2, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err2 == nil {
		return key2, nil
	}
	key3, err3 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err3 != nil {
		return nil, fmt.Errorf("decoding private key failed with %s (ec) and %s (rsa PKCS1) and %s (PKCS8)", err, err2, err3)
	}
	return key3, nil
}
