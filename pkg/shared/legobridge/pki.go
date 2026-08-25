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
	"slices"
	"time"

	"github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/go-acme/lego/v5/certificate"
	"k8s.io/utils/ptr"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
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
)

// issueSignedCert does all the Certificate Issuing.
func issueSignedCert(csr *x509.CertificateRequest, isCA bool, privKey crypto.Signer, privKeyPEM []byte, signerKeyPair *TLSKeyPair, duration time.Duration, usages []v1alpha1.KeyUsage) (*certificate.Resource, error) {
	csrPEM, err := generateCSRPEM(csr, privKey)
	if err != nil {
		return nil, err
	}
	crt, err := generateCertFromCSR(csrPEM, duration, isCA, usages)
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
	// Include the remaining certificates of the CA's own chain, so that TLS servers
	// using the issued certificate present a complete chain up to (but excluding)
	// the root. Without this, clients trusting only the root cannot build a path
	// when the signing CA is itself an intermediate.
	for i := range signerKeyPair.Chain {
		chainCert := &signerKeyPair.Chain[i]
		if isSelfSignedCert(chainCert) {
			// Roots are trust anchors on the client side; serving them is pointless.
			continue
		}
		if err := encodeCertPEM(issuerPEM, chainCert.Raw); err != nil {
			return nil, err
		}
	}

	// Return chain: leaf certificate + issuer certificate (+ issuer chain)
	crtPEM = append(crtPEM, issuerPEM.Bytes()...)

	return &certificate.Resource{
		PrivateKey:        privKeyPEM,
		Certificate:       crtPEM,
		IssuerCertificate: issuerPEM.Bytes(),
		CSR:               csrPEM,
	}, nil
}

// isSelfSignedCert returns true if the certificate is self-signed (subject equals
// issuer), i.e. typically a root CA certificate.
func isSelfSignedCert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func defaultCertificatePrivateKeyDefaults() CertificatePrivateKeyDefaults {
	return CertificatePrivateKeyDefaults{
		algorithm:    v1alpha1.RSAKeyAlgorithm,
		ecdsaKeySize: 384,
		rsaKeySize:   2048,
	}
}

// GenerateKey generates a crypto.Signer key and its PEM encoded format.
func GenerateKey(algo x509.PublicKeyAlgorithm, size int, usePKCS8 bool) (crypto.Signer, []byte, error) {
	input := &v1alpha1.CertificatePrivateKey{}
	switch algo {
	case x509.ECDSA:
		input.Algorithm = ptr.To(v1alpha1.ECDSAKeyAlgorithm)
	case x509.RSA:
		input.Algorithm = ptr.To(v1alpha1.RSAKeyAlgorithm)
	default:
		return nil, nil, fmt.Errorf("unsupported public key algorithm: %v", algo)
	}
	if size != 0 {
		// precheck for type conversion
		if size < 0 || size > 4096 {
			return nil, nil, fmt.Errorf("invalid key size: %d", size)
		}
		input.Size = new(v1alpha1.PrivateKeySize(size))
	}
	input.Encoding = v1alpha1.PKCS1
	if usePKCS8 {
		input.Encoding = v1alpha1.PKCS8
	}
	defaults := defaultCertificatePrivateKeyDefaults()
	keySpec, err := defaults.ToKeySpec(input)
	if err != nil {
		return nil, nil, err
	}
	return GenerateKeyFromSpec(keySpec)
}

// GenerateKeyFromSpec generates a crypto.Signer key and its PEM encoded format.
func GenerateKeyFromSpec(keySpec KeySpec) (crypto.Signer, []byte, error) {
	key, err := generatePrivateKey(keySpec.KeyType)
	if err != nil {
		return nil, nil, err
	}

	pem, err := privateKeyToBytes(key, keySpec.UsePKCS8)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding private key failed: %w", err)
	}
	return key, pem, nil
}

// createCertReq creates a x509.CertificateRequest template that can be used
// to generate a PEM encoded CSR.
func createCertReq(input ObtainInput) (*x509.CertificateRequest, error) {
	subjectCA := &input.CAKeyPair.Cert.Subject
	privateKey, err := generatePrivateKey(input.KeySpec.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key for type %v: %w", input.KeySpec.KeyType, err)
	}

	var emailAddresses []string
	emailAddresses = append(emailAddresses, input.CAKeyPair.Cert.EmailAddresses...)
	emailAddresses = append(emailAddresses, input.EmailAddresses...)

	csr := &x509.CertificateRequest{
		Version:            3,
		PublicKeyAlgorithm: getPublicKeyAlgorithm(privateKey),
		PublicKey:          privateKey.Public(),
		EmailAddresses:     emailAddresses,
		IPAddresses:        input.IPAddresses,
		URIs:               input.URIs,
	}

	// When the request specifies an explicit subject (structured or literal), honor
	// it. Otherwise fall back to the common name plus the subject attributes copied
	// from the signing CA (backward-compatible default).
	if input.Subject != nil || input.LiteralSubject != nil {
		subject, rawSubject, err := subjectFromInput(input)
		if err != nil {
			return nil, err
		}
		csr.Subject = subject
		// Preserve the exact DN (attribute order and non-structured attribute types)
		// for a literal subject; without RawSubject the CSR would re-encode the
		// subject in Go's canonical field order.
		csr.RawSubject = rawSubject
	} else {
		csr.Subject = pkix.Name{
			CommonName:         ptr.Deref(input.CommonName, ""),
			Country:            subjectCA.Country,
			Organization:       subjectCA.Organization,
			OrganizationalUnit: subjectCA.OrganizationalUnit,
			Locality:           subjectCA.Locality,
			Province:           subjectCA.Province,
			StreetAddress:      subjectCA.StreetAddress,
			PostalCode:         subjectCA.PostalCode,
		}
	}

	// For leaf certificates, ensure the common name is also present as a DNS SAN.
	// Modern TLS clients ignore the certificate's common name and validate the
	// requested hostname only against the subject alternative names; a Certificate
	// that sets only `commonName` (and no `dnsNames`) would otherwise yield a
	// certificate that browsers reject with ERR_CERT_COMMON_NAME_INVALID. This
	// matches the ACME issuance path, which already includes the common name in the
	// set of domains. CA certificates are excluded: their common name is an
	// identity, not a hostname. For a literalSubject the common name is extracted
	// from the parsed DN (see subjectFromInput) and promoted the same way.
	dnsNames := input.DNSNames
	if cn := csr.Subject.CommonName; !input.IsCA && cn != "" && !slices.Contains(dnsNames, cn) {
		dnsNames = append([]string{cn}, dnsNames...)
	}

	csr.DNSNames = dnsNames

	return csr, nil
}

// subjectFromInput builds the pkix.Name subject from the input.
// If LiteralSubject is set, it is parsed as an LDAP DN and its attributes
// (including the common name) are populated into the returned pkix.Name. In that
// case rawSubject holds the DER encoding of the parsed RDN sequence: callers must
// set it as the RawSubject of the x509 certificate/CSR template so that the exact
// attribute order (and attribute types without a dedicated pkix.Name field, e.g.
// domainComponent) is preserved. Without it, Go re-marshals the subject from the
// structured pkix.Name fields in its own canonical order, silently reordering and
// dropping attributes.
// Otherwise a pkix.Name is assembled from CommonName and the optional structured
// Subject attributes and rawSubject is nil.
// Mutual exclusivity of Subject/LiteralSubject/CommonName is enforced upstream by
// utils.ValidateSubjectExclusivity.
func subjectFromInput(input ObtainInput) (subject pkix.Name, rawSubject []byte, err error) {
	if input.LiteralSubject != nil && *input.LiteralSubject != "" {
		rdns, err := pki.UnmarshalSubjectStringToRDNSequence(*input.LiteralSubject)
		if err != nil {
			return pkix.Name{}, nil, fmt.Errorf("parsing literalSubject failed: %w", err)
		}
		subject.FillFromRDNSequence(&rdns)
		rawSubject, err = pki.MarshalRDNSequenceToRawDERBytes(rdns)
		if err != nil {
			return pkix.Name{}, nil, fmt.Errorf("encoding literalSubject failed: %w", err)
		}
		return subject, rawSubject, nil
	}

	subject = pkix.Name{CommonName: ptr.Deref(input.CommonName, "")}
	if s := input.Subject; s != nil {
		subject.Organization = s.Organizations
		subject.Country = s.Countries
		subject.OrganizationalUnit = s.OrganizationalUnits
		subject.Locality = s.Localities
		subject.Province = s.Provinces
		subject.StreetAddress = s.StreetAddresses
		subject.PostalCode = s.PostalCodes
		subject.SerialNumber = s.SerialNumber
	}
	return subject, nil, nil
}

func generatePrivateKey(keyType KeyType) (crypto.Signer, error) {
	switch keyType {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("invalid key type: %v", keyType)
	}
}

func getPublicKeyAlgorithm(privateKey crypto.Signer) x509.PublicKeyAlgorithm {
	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
		return x509.ECDSA
	case *rsa.PrivateKey:
		return x509.RSA
	default:
		return x509.UnknownPublicKeyAlgorithm
	}
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
func generateCertFromCSR(csrPEM []byte, duration time.Duration, isCA bool, usages []v1alpha1.KeyUsage) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	csr, err := extractCertificateRequest(csrPEM)
	if err != nil {
		return nil, err
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}

	ku, eku, err := buildDefaultedKeyUsages(usages, isCA, csr.PublicKeyAlgorithm == x509.RSA, DefaultCertExtKeyUsage)
	if err != nil {
		return nil, err
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
		RawSubject:            csr.RawSubject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		URIs:                  csr.URIs,
	}, nil
}

// NewSelfSignedCertInPEMFormat returns a self-signed certificate and the private key in PEM format.
func NewSelfSignedCertInPEMFormat(input ObtainInput) (pkix.Name, []byte, []byte, error) {
	hasLiteralSubject := input.LiteralSubject != nil && *input.LiteralSubject != ""
	if input.CommonName == nil && !hasLiteralSubject {
		return pkix.Name{}, nil, nil, fmt.Errorf("common name or literal subject must be set")
	}
	if input.Duration == nil {
		return pkix.Name{}, nil, nil, fmt.Errorf("duration must be set")
	}
	certPrivateKey, certPrivateKeyPEM, err := GenerateKeyFromSpec(input.KeySpec)
	if err != nil {
		return pkix.Name{}, nil, nil, err
	}

	// Self-signed certificates are always CAs here, so KeyCertSign is always
	// included. When the request does not specify any usages the historical
	// defaults are applied (server authentication, plus key encipherment for RSA).
	isRSA := getPublicKeyAlgorithm(certPrivateKey) == x509.RSA
	keyUsage, extKeyUsage, err := buildDefaultedKeyUsages(input.Usages, true, isRSA, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	if err != nil {
		return pkix.Name{}, nil, nil, err
	}

	subject, rawSubject, err := subjectFromInput(input)
	if err != nil {
		return pkix.Name{}, nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		// Preserve the exact DN for a literal subject (see subjectFromInput).
		RawSubject:            rawSubject,
		DNSNames:              input.DNSNames,
		EmailAddresses:        input.EmailAddresses,
		IPAddresses:           input.IPAddresses,
		URIs:                  input.URIs,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(*input.Duration),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDerBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, certPrivateKey.Public(), certPrivateKey)
	if err != nil {
		return pkix.Name{}, nil, nil, fmt.Errorf("error creating x509 certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDerBytes})
	return subject, certPEM, certPrivateKeyPEM, nil
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
func PublicKeyFromPrivateKey(key any) (crypto.PublicKey, error) {
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

// buildDefaultedKeyUsages converts the requested api.KeyUsage values to
// x509.KeyUsage and []x509.ExtKeyUsage and fills in sensible defaults so that the
// resulting certificate is usable for TLS regardless of which usages were
// requested.
//
//   - When no usages are requested, the historical defaults are returned:
//     digital signature (+ key encipherment for RSA keys) as key usage and the
//     caller-provided defaultExtKeyUsage as extended key usage.
//   - When usages are requested but none of them is a basic key usage, the base
//     key usage default (digital signature, + key encipherment for RSA keys) is
//     added, since a certificate without any basic key usage bits cannot be used
//     for a TLS handshake.
//   - When usages are requested but none of them is an extended key usage, the
//     extended key usage is left empty (the caller explicitly restricted usage to
//     the requested basic key usages).
//
// When isCA is true, x509.KeyUsageCertSign is always included so the certificate
// can sign other certificates.
func buildDefaultedKeyUsages(usages []v1alpha1.KeyUsage, isCA, isRSA bool, defaultExtKeyUsage []x509.ExtKeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	if len(usages) == 0 {
		ku := DefaultCertKeyUsage
		if isRSA {
			ku |= RSAKeyUsage
		}
		if isCA {
			ku |= CAKeyUsage
		}
		return ku, slices.Clone(defaultExtKeyUsage), nil
	}

	ku, eku, err := buildKeyUsages(usages, isCA)
	if err != nil {
		return 0, nil, err
	}

	// Ensure at least the basic key usage bits required for TLS are present when the
	// request specified only extended key usages.
	basicMask := ku &^ CAKeyUsage
	if basicMask == 0 {
		ku |= DefaultCertKeyUsage
		if isRSA {
			ku |= RSAKeyUsage
		}
	}
	return ku, eku, nil
}

// buildKeyUsages converts api.KeyUsage values to x509.KeyUsage and []x509.ExtKeyUsage.
// Defaults to digital signature + key encipherment when the slice is empty.
// When isCA is true, x509.KeyUsageCertSign is always included so the certificate
// can sign other certificates.
func buildKeyUsages(usages []v1alpha1.KeyUsage, isCA bool) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	if len(usages) == 0 {
		ku := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		if isCA {
			ku |= CAKeyUsage
		}
		return ku, nil, nil
	}

	var ku x509.KeyUsage
	var eku []x509.ExtKeyUsage
	var unknown []v1alpha1.KeyUsage

	keyUsageMap := map[v1alpha1.KeyUsage]x509.KeyUsage{
		v1alpha1.UsageSigning:           x509.KeyUsageDigitalSignature,
		v1alpha1.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
		v1alpha1.UsageContentCommitment: x509.KeyUsageContentCommitment,
		v1alpha1.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
		v1alpha1.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
		v1alpha1.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
		v1alpha1.UsageCertSign:          x509.KeyUsageCertSign,
		v1alpha1.UsageCRLSign:           x509.KeyUsageCRLSign,
		v1alpha1.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
		v1alpha1.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
	}
	extKeyUsageMap := map[v1alpha1.KeyUsage]x509.ExtKeyUsage{
		v1alpha1.UsageAny:             x509.ExtKeyUsageAny,
		v1alpha1.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
		v1alpha1.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
		v1alpha1.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
		v1alpha1.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
		v1alpha1.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
		v1alpha1.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
		v1alpha1.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
		v1alpha1.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
		v1alpha1.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
		v1alpha1.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
		v1alpha1.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
		v1alpha1.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
	}

	for _, u := range usages {
		if kuse, ok := keyUsageMap[u]; ok {
			ku |= kuse
		} else if ekuse, ok := extKeyUsageMap[u]; ok {
			eku = append(eku, ekuse)
		} else {
			unknown = append(unknown, u)
		}
	}

	if len(unknown) > 0 {
		return 0, nil, fmt.Errorf("unknown key usages: %v", unknown)
	}
	if isCA {
		ku |= CAKeyUsage
	}
	return ku, eku, nil
}

// pubKeySize returns the bit size of a key
func pubKeySize(key any) int {
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
	// All standard library public key types (rsa, ecdsa, ed25519, ecdh) implement
	// an Equal method. Using it avoids operating on the raw, now-deprecated key
	// coordinates (e.g. ecdsa.PublicKey.X/Y) and safely handles mismatched types.
	type equalKey interface {
		Equal(x crypto.PublicKey) bool
	}
	key, ok := a.(equalKey)
	if !ok {
		return false, fmt.Errorf("unrecognised public key type")
	}
	return key.Equal(b), nil
}

func pemBlockForKeyPKCS1(priv any) (*pem.Block, error) {
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

func privateKeyToBytes(key crypto.PrivateKey, usePKCS8 bool) ([]byte, error) {
	if usePKCS8 {
		return pki.EncodePKCS8PrivateKey(key)
	}
	block, err := pemBlockForKeyPKCS1(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// BytesToPrivateKey decodes a PEM encoded private key.
func BytesToPrivateKey(data []byte) (crypto.Signer, error) {
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
	signer, ok := key3.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return signer, nil
}
