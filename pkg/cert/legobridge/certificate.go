/*
 * SPDX-FileCopyrightText: 2020 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package legobridge

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	api "github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/utils"
)

// TLSCAKey is the secret data key for the CA key.
const TLSCAKey = "ca.crt"

// ObtainerCallback is callback function type
type ObtainerCallback func(output *ObtainOutput)

// ObtainInput contains all data needed to obtain a certificate.
type ObtainInput struct {
	// User is the registration user.
	User *RegistrationUser
	// CAKeyPair are the private key and the public key cert of the CA.
	CAKeyPair *TLSKeyPair
	// DNSSettings are the settings for the DNSController.
	DNSSettings *DNSControllerSettings
	// IssuerKey is a cluster-aware key of the issuer to use.
	IssuerKey utils.IssuerKeyItf
	// CommonName is the CN.
	CommonName *string
	// DNSNames are optional domain names.
	DNSNames []string
	// CSR is the optional Certificate Signing Request.
	CSR []byte
	// Request name is the request object name.
	RequestName resources.ObjectName
	// TargetClass is the target class of the DNSEntry.
	TargetClass string
	// Callback is the callback function to return the ObtainOutput.
	Callback ObtainerCallback
	// PreflightCheck performs if request is allowed to be processed (e.g. quota check).
	PreflightCheck func() error
	// Renew is flag if it is a renew request.
	Renew bool
	// AlwaysDeactivateAuthorizations deactivates authorizations to avoid their caching
	AlwaysDeactivateAuthorizations bool
	// PreferredChain
	PreferredChain string
	// KeyType represents the algo and size to use for the private key (only used if CSR is not set).
	KeyType certcrypto.KeyType
	// IsCA is used to request a self-signed certificate
	IsCA bool
	// Duration is the lifetime of the certificate
	Duration *time.Duration
}

// DNSControllerSettings are the settings for the DNSController.
type DNSControllerSettings struct {
	// Cluster is the cluster where the DNSEntries will be created
	Cluster resources.Cluster
	// Namespace to set for challenge DNSEntry
	Namespace string
	// OwnerID to set for challenge DNSEntry
	// +optional
	OwnerID *string
	// PrecheckNameservers for checking DNS propagation of DNS challenge TXT record
	PrecheckNameservers []string
	// AdditionalWait is the additional wait time after DNS propagation
	// to wait for "last mile" propagation to DNS server used by the ACME server
	AdditionalWait time.Duration
	// PropagationTimeout is the propagation timeout for the DNS challenge.
	PropagationTimeout time.Duration
	// FollowCNAME if true checks and follows CNAME records for DNS01 challenge domains.
	FollowCNAME bool
	// DNSRecordSettings are additional fields needed to create a DNSRecord. If set, DNSChallenge will use DNSRecords instead of DNSEntries.
	DNSRecordSettings *DNSRecordSettings
}

// DNSRecordSettings are additional fields needed to create a DNSRecord.
type DNSRecordSettings struct {
	// Type is the provider type.
	Type string
	// SecretRef is a reference to a secret that contains the cloud provider specific credentials.
	SecretRef corev1.SecretReference
	// Class is the optional extension class for the DNS record.
	Class string
}

// ObtainOutput is the result of the certificate obtain request.
type ObtainOutput struct {
	// Certificates contains the certificates.
	Certificates *certificate.Resource
	// IssuerInfo is the name and type of the issuer.
	IssuerInfo utils.IssuerInfo
	// CommonName is the copy from the input.
	CommonName *string
	// DNSNames are the copies from the input.
	DNSNames []string
	// CSR is the copy from the input.
	CSR []byte
	// KeyType is the copy from the input.
	KeyType certcrypto.KeyType
	// IsCA is used to request a self-signed certificate
	IsCA bool
	// Err contains the obtain request error.
	Err error
}

// Obtainer provides a Obtain method to start a certificate request
type Obtainer interface {
	// Obtain starts the async obtain request.
	Obtain(input ObtainInput) error
}

// ConcurrentObtainError is returned if Obtain should be postponed because of concurrent obtain request for
// at least one domain name.
type ConcurrentObtainError struct {
	// DomainName is the domain name concurrently requested
	DomainName string
}

// CertificatePrivateKeyDefaults contains default algorithms and sizes for new private keys.
// These defaults are only used for new certificates or on renewal.
type CertificatePrivateKeyDefaults struct {
	algorithm    api.PrivateKeyAlgorithm
	rsaKeySize   api.PrivateKeySize
	ecdsaKeySize api.PrivateKeySize
}

func (d *ConcurrentObtainError) Error() string {
	return fmt.Sprintf("concurrent obtain for domain name %s", d.DomainName)
}

type obtainer struct {
	lock           sync.Mutex
	pendingDomains map[string]time.Time
}

// NewObtainer creates a new Obtainer
func NewObtainer() Obtainer {
	return &obtainer{pendingDomains: map[string]time.Time{}}
}

func obtainForDomains(client *lego.Client, domains []string, input ObtainInput) (*certificate.Resource, error) {
	privateKey, err := certcrypto.GeneratePrivateKey(input.KeyType)
	if err != nil {
		return nil, err
	}
	request := certificate.ObtainRequest{
		Domains:                        domains,
		Bundle:                         true,
		AlwaysDeactivateAuthorizations: input.AlwaysDeactivateAuthorizations,
		PreferredChain:                 input.PreferredChain,
		PrivateKey:                     privateKey,
	}
	if input.PreflightCheck != nil {
		if err := input.PreflightCheck(); err != nil {
			return nil, err
		}
	}
	return client.Certificate.Obtain(request)
}

// NewCertificatePrivateKeyDefaults creates a defaults for certifcate private key generation.
func NewCertificatePrivateKeyDefaults(algorithm api.PrivateKeyAlgorithm, rsaKeySize, ecdsaKeySize api.PrivateKeySize) (*CertificatePrivateKeyDefaults, error) {
	if algorithm != api.RSAKeyAlgorithm && algorithm != api.ECDSAKeyAlgorithm {
		return nil, fmt.Errorf("invalid algoritm: '%s' (allowed values: '%s' and '%s')", algorithm, api.RSAKeyAlgorithm, api.ECDSAKeyAlgorithm)
	}
	if rsaKeySize != 2048 && rsaKeySize != 3072 && rsaKeySize != 4096 {
		return nil, fmt.Errorf("invalid RSA private key size: %d (allowed values: 2048, 3072, 4096)", rsaKeySize)
	}
	if ecdsaKeySize != 256 && ecdsaKeySize != 384 {
		return nil, fmt.Errorf("invalid ECDSA private key size: %d (allowed values: 256, 384)", ecdsaKeySize)
	}
	return &CertificatePrivateKeyDefaults{
		algorithm:    algorithm,
		rsaKeySize:   rsaKeySize,
		ecdsaKeySize: ecdsaKeySize,
	}, nil
}

func (d CertificatePrivateKeyDefaults) String() string {
	return fmt.Sprintf("Defaults for certificate private keys: algorithm=%s, RSA key size=%d, ECDSA key size=%d",
		d.algorithm, d.rsaKeySize, d.ecdsaKeySize)
}

// ToKeyType extracts the key type from the private key spec.
func (d CertificatePrivateKeyDefaults) ToKeyType(privateKeySpec *api.CertificatePrivateKey) (certcrypto.KeyType, error) {
	algorithm := d.algorithm
	if privateKeySpec != nil && privateKeySpec.Algorithm != nil {
		algorithm = *privateKeySpec.Algorithm
	}
	var defaultSize api.PrivateKeySize
	switch algorithm {
	case api.RSAKeyAlgorithm:
		defaultSize = d.rsaKeySize
	case api.ECDSAKeyAlgorithm:
		defaultSize = d.ecdsaKeySize
	default:
		return "", fmt.Errorf("invalid private key algorithm %s (allowed values are '%s' and '%s')",
			algorithm, api.RSAKeyAlgorithm, api.ECDSAKeyAlgorithm)
	}
	size := defaultSize
	if privateKeySpec != nil && privateKeySpec.Size != nil {
		size = *privateKeySpec.Size
	}

	switch algorithm {
	case api.RSAKeyAlgorithm:
		switch size {
		case 2048:
			return certcrypto.RSA2048, nil
		case 3072:
			return certcrypto.RSA3072, nil
		case 4096:
			return certcrypto.RSA4096, nil
		default:
			return "", fmt.Errorf("invalid key size for RSA: %d (allowed values are 2048, 3072, and 4096)", size)
		}
	case api.ECDSAKeyAlgorithm:
		switch size {
		case 256:
			return certcrypto.EC256, nil
		case 384:
			return certcrypto.EC384, nil
		default:
			return "", fmt.Errorf("invalid key size for ECDSA: %d (allowed values are 256 and 384)", size)
		}
	default:
		return "", fmt.Errorf("invalid private key algorithm %s (allowed values are '%s' and '%s')",
			algorithm, api.RSAKeyAlgorithm, api.ECDSAKeyAlgorithm)
	}
}

// IsDefaultKeyType returns true if the keyType matched the default one.
func (d CertificatePrivateKeyDefaults) IsDefaultKeyType(keyType certcrypto.KeyType) bool {
	defaultKeyType, err := d.ToKeyType(nil)
	if err != nil {
		return false
	}
	return defaultKeyType == keyType
}

// FromKeyType converts key type back to a private key spec.
func FromKeyType(keyType certcrypto.KeyType) *api.CertificatePrivateKey {
	switch keyType {
	case certcrypto.RSA2048:
		return newCertificatePrivateKey(api.RSAKeyAlgorithm, 2048)
	case certcrypto.RSA3072:
		return newCertificatePrivateKey(api.RSAKeyAlgorithm, 3072)
	case certcrypto.RSA4096:
		return newCertificatePrivateKey(api.RSAKeyAlgorithm, 4096)
	case certcrypto.EC256:
		return newCertificatePrivateKey(api.ECDSAKeyAlgorithm, 256)
	case certcrypto.EC384:
		return newCertificatePrivateKey(api.ECDSAKeyAlgorithm, 384)
	default:
		return nil
	}
}

func newCertificatePrivateKey(algorithm api.PrivateKeyAlgorithm, size api.PrivateKeySize) *api.CertificatePrivateKey {
	return &api.CertificatePrivateKey{Algorithm: ptr.To(algorithm), Size: ptr.To(size)}
}

func obtainForCSR(client *lego.Client, csr []byte, input ObtainInput) (*certificate.Resource, error) {
	cert, err := extractCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	if input.PreflightCheck != nil {
		if err := input.PreflightCheck(); err != nil {
			return nil, err
		}
	}
	return client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:                            cert,
		Bundle:                         true,
		AlwaysDeactivateAuthorizations: input.AlwaysDeactivateAuthorizations,
		PreferredChain:                 input.PreferredChain,
	})
}

func extractCertificateRequest(csr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, fmt.Errorf("decoding CSR failed")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

type dummyProvider struct {
	count int
}

var _ ProviderWithCount = &dummyProvider{}

func (p *dummyProvider) Present(_, _, _ string) error {
	p.count++
	return nil
}

func (p *dummyProvider) CleanUp(_, _, _ string) error {
	return nil
}

func (p *dummyProvider) GetChallengesCount() int {
	return p.count
}

func (p *dummyProvider) GetPendingTXTRecordError() error {
	return nil
}

func (o *obtainer) Obtain(input ObtainInput) error {
	switch {
	case input.User != nil:
		return o.ObtainACME(input)
	case input.CAKeyPair != nil:
		return o.ObtainFromCA(input)
	case input.IsCA:
		return o.ObtainFromSelfSigned(input)
	default:
		return fmt.Errorf("Certificate obtention not valid, neither ACME, CA  or selfSigned values were provided")
	}
}

// ObtainACME starts the async obtain request.
func (o *obtainer) ObtainACME(input ObtainInput) error {
	err := o.setPending(input)
	if err != nil {
		return err
	}
	config := input.User.NewConfig(input.User.CADirURL())

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		o.releasePending(input)
		return err
	}

	var provider ProviderWithCount
	if input.DNSSettings != nil {
		provider, err = newDelegatingProvider(*input.DNSSettings, input.RequestName,
			input.TargetClass, input.IssuerKey)
		if err != nil {
			o.releasePending(input)
			return err
		}
		err = client.Challenge.SetDNS01Provider(provider,
			dns01.AddRecursiveNameservers(input.DNSSettings.PrecheckNameservers),
			utils.CreateWrapPreCheckOption(input.DNSSettings.PrecheckNameservers))
		if err != nil {
			o.releasePending(input)
			return err
		}
	} else {
		// skipDNSChallengeValidation
		provider = &dummyProvider{}
		err = client.Challenge.SetDNS01Provider(provider, utils.NoPropagationCheckOption())
		if err != nil {
			o.releasePending(input)
			return err
		}
	}

	go func() {
		var certificates *certificate.Resource
		var err error
		if input.CSR == nil {
			domains := input.DNSNames
			if input.CommonName != nil {
				domains = append([]string{*input.CommonName}, domains...)
			}
			certificates, err = obtainForDomains(client, domains, input)
		} else {
			certificates, err = obtainForCSR(client, input.CSR, input)
		}
		count := provider.GetChallengesCount()
		metrics.AddACMEOrder(input.IssuerKey, err == nil, count, input.Renew)
		output := &ObtainOutput{
			Certificates: certificates,
			IssuerInfo:   utils.NewACMEIssuerInfo(input.IssuerKey),
			CommonName:   input.CommonName,
			DNSNames:     input.DNSNames,
			KeyType:      input.KeyType,
			CSR:          input.CSR,
			Err:          niceError(err, provider.GetPendingTXTRecordError()),
		}
		input.Callback(output)
		o.releasePending(input)
	}()

	return nil
}

// ObtainFromCA start the certificate creation from a CA
func (o *obtainer) ObtainFromCA(input ObtainInput) error {
	err := o.setPending(input)
	if err != nil {
		return err
	}

	go func() {
		var certificates *certificate.Resource
		var err error

		certificates, err = newCASignedCertFromInput(input)
		output := &ObtainOutput{
			Certificates: certificates,
			IssuerInfo:   utils.NewCAIssuerInfo(input.IssuerKey),
			CommonName:   input.CommonName,
			DNSNames:     input.DNSNames,
			CSR:          input.CSR,
			Err:          err,
		}
		input.Callback(output)
		o.releasePending(input)
	}()

	return nil
}

func (o *obtainer) setPending(input ObtainInput) error {
	o.lock.Lock()
	defer o.lock.Unlock()

	names, err := o.collectDomainNames(input)
	if err != nil {
		return err
	}
	now := time.Now()
	outdated := now.Add(-10 * time.Minute)
	for _, name := range names {
		t, ok := o.pendingDomains[name]
		// checking for outdated is only defensive programming
		if ok && t.After(outdated) {
			return &ConcurrentObtainError{DomainName: name}
		}
	}
	for _, name := range names {
		o.pendingDomains[name] = now
	}
	return nil
}

func (o *obtainer) releasePending(input ObtainInput) {
	o.lock.Lock()
	defer o.lock.Unlock()

	names, _ := o.collectDomainNames(input)
	for _, name := range names {
		delete(o.pendingDomains, name)
	}
}

func (o *obtainer) collectDomainNames(input ObtainInput) ([]string, error) {
	if input.CSR == nil {
		if input.CommonName != nil {
			return append([]string{*input.CommonName}, input.DNSNames...), nil
		}
		return input.DNSNames, nil
	}
	cn, san, err := utils.ExtractCommonNameAnDNSNames(input.CSR)
	if err != nil {
		return nil, err
	}
	if cn != nil {
		return append([]string{*cn}, san...), nil
	}
	return san, nil
}

// ObtainFromSelfSigned starts the creation of a selfsigned certificate
func (o *obtainer) ObtainFromSelfSigned(input ObtainInput) error {
	go func() {
		certificates, err := newSelfSignedCertFromInput(input)
		output := &ObtainOutput{
			Certificates: certificates,
			IssuerInfo:   utils.NewSelfSignedIssuerInfo(input.IssuerKey),
			CommonName:   input.CommonName,
			DNSNames:     input.DNSNames,
			KeyType:      input.KeyType,
			IsCA:         input.IsCA,
			CSR:          input.CSR,
			Err:          err,
		}
		input.Callback(output)
	}()
	return nil
}

func newSelfSignedCertFromInput(input ObtainInput) (certificates *certificate.Resource, err error) {
	var certPEM, privKeyPEM []byte
	if input.CSR != nil {
		certPEM, privKeyPEM, err = newSelfSignedCertFromCSRinPEMFormat(input)
	} else {
		certPrivateKey := FromKeyType(input.KeyType)
		if certPrivateKey == nil {
			return nil, fmt.Errorf("invalid key type: '%s'", input.KeyType)
		}
		var algo x509.PublicKeyAlgorithm
		switch *certPrivateKey.Algorithm {
		case api.RSAKeyAlgorithm:
			algo = x509.RSA
		case api.ECDSAKeyAlgorithm:
			algo = x509.ECDSA
		}
		certPEM, privKeyPEM, err = newSelfSignedCertInPEMFormat(input, algo, int(*certPrivateKey.Size))
	}
	if err != nil {
		return nil, err
	}

	return &certificate.Resource{
		PrivateKey:        privKeyPEM,
		Certificate:       certPEM,
		IssuerCertificate: certPEM,
	}, nil
}

func newSelfSignedCertFromCSRinPEMFormat(input ObtainInput) ([]byte, []byte, error) {
	csr, err := extractCertificateRequest(input.CSR)
	if err != nil {
		return nil, nil, err
	}
	pubKeySize := pubKeySize(csr.PublicKey)
	if pubKeySize == 0 {
		pubKeySize = defaultKeySize(csr.PublicKeyAlgorithm)
	}
	certPrivateKey, certPrivateKeyPEM, err := GenerateKey(csr.PublicKeyAlgorithm, pubKeySize)
	if err != nil {
		return nil, nil, err
	}
	csrPEM, err := generateCSRPEM(csr, certPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	if input.Duration == nil {
		return nil, nil, fmt.Errorf("duration must be set")
	}
	crt, err := generateCertFromCSR(csrPEM, *input.Duration, true)
	if err != nil {
		return nil, nil, err
	}
	crtPEM, err := signCert(crt, crt, certPrivateKey.Public(), certPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return crtPEM, certPrivateKeyPEM, nil
}

// CertificatesToSecretData converts a certificate resource to secret data.
func CertificatesToSecretData(certificates *certificate.Resource) map[string][]byte {
	data := map[string][]byte{}

	data[corev1.TLSCertKey] = certificates.Certificate
	data[corev1.TLSPrivateKeyKey] = certificates.PrivateKey
	data[TLSCAKey] = certificates.IssuerCertificate

	return data
}

// SecretDataToCertificates converts secret data to a certificate resource.
func SecretDataToCertificates(data map[string][]byte) *certificate.Resource {
	certificates := &certificate.Resource{}
	certificates.Certificate = data[corev1.TLSCertKey]
	certificates.PrivateKey = data[corev1.TLSPrivateKeyKey]
	certificates.IssuerCertificate = data[TLSCAKey]
	return certificates
}

// DecodeCertificateFromSecretData decodes the cert key from secret data to a x509 certificate.
func DecodeCertificateFromSecretData(data map[string][]byte) (*x509.Certificate, error) {
	tlsCrt, ok := data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("fetching %s from request secret failed", corev1.TLSCertKey)
	}
	return DecodeCertificate(tlsCrt)
}

// DecodeCertificate decodes the crt byte array.
func DecodeCertificate(tlsCrt []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(tlsCrt)
	if block == nil {
		return nil, fmt.Errorf("decoding pem for %s from request secret failed", corev1.TLSCertKey)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate failed: %w", err)
	}
	return cert, nil
}

// newCASignedCertFromInput returns a new Certificate signed by a CA.
// An x509.CertificateRequest is created from scratch based on and ObtainInput object
func newCASignedCertFromInput(input ObtainInput) (*certificate.Resource, error) {
	var csr *x509.CertificateRequest
	var err error
	if input.CSR == nil {
		csr, err = createCertReq(input)
	} else {
		csr, err = extractCertificateRequest(input.CSR)
	}
	if err != nil {
		return nil, err
	}
	return newCASignedCertFromCertReq(csr, input.CAKeyPair, input.Duration)
}

// newCASignedCertFromCertReq returns a new Certificate signed by a CA based on
// an x509.CertificateRequest and a CA key pair. A private key will be generated.
func newCASignedCertFromCertReq(csr *x509.CertificateRequest, CAKeyPair *TLSKeyPair, duration *time.Duration) (*certificate.Resource, error) {
	pubKeySize := pubKeySize(csr.PublicKey)
	if pubKeySize == 0 {
		pubKeySize = defaultKeySize(csr.PublicKeyAlgorithm)
	}
	privKey, privKeyPEM, err := GenerateKey(csr.PublicKeyAlgorithm, pubKeySize)
	if err != nil {
		return nil, err
	}
	if duration == nil {
		return nil, fmt.Errorf("duration must be set")
	}
	return issueSignedCert(csr, false, privKey, privKeyPEM, CAKeyPair, *duration)
}

// RevokeCertificate revokes a certificate
func RevokeCertificate(user *RegistrationUser, cert []byte) error {
	config := user.NewConfig(user.CADirURL())

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("client creation failed: %w", err)
	}

	return client.Certificate.Revoke(cert)
}

func niceError(err, detailErr error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	part := "time limit exceeded: last error: %!w(<nil>)"
	if strings.Contains(msg, part) {
		msg = strings.ReplaceAll(msg, part, "timeout of DNS propagation check")
	}

	if detailErr != nil {
		msg = fmt.Sprintf("%s. Details: %s", msg, detailErr)
	}
	msg = strings.ReplaceAll(msg, "\n", " ")

	return fmt.Errorf("%s", msg)
}
