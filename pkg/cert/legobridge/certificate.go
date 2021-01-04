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
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/gardener/cert-management/pkg/cert/metrics"
	"github.com/gardener/cert-management/pkg/cert/utils"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/resources"
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
	// DNSCluster is the cluster to use for writing DNS entries for DNS challenges.
	DNSCluster resources.Cluster
	// DNSSettings are the settings for the DNSController.
	DNSSettings DNSControllerSettings
	// CaDirURL is the URL of the ACME CA directory.
	CaDirURL string
	// IssuerName is the name of the issuer to use.
	IssuerName string
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
	// RenewCert is the certificate to renew.
	RenewCert *certificate.Resource
}

// DNSControllerSettings are the settings for the DNSController.
type DNSControllerSettings struct {
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
	// Renew is the flag if this was a renew request.
	Renew bool
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

func obtainForDomains(client *lego.Client, domains []string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	return client.Certificate.Obtain(request)
}

func obtainForCSR(client *lego.Client, csr []byte) (*certificate.Resource, error) {
	cert, err := extractCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	return client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:            cert,
		Bundle:         true,
		PreferredChain: "",
	})
}

func extractCertificateRequest(csr []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, fmt.Errorf("decoding CSR failed")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func renew(client *lego.Client, renewCert *certificate.Resource) (*certificate.Resource, error) {
	return client.Certificate.Renew(*renewCert, true, false, "")
}

func (o *obtainer) Obtain(input ObtainInput) error {
	switch {
	case input.User != nil:
		return o.ObtainACME(input)
	case input.CAKeyPair != nil:
		return o.ObtainFromCA(input)
	default:
		return fmt.Errorf("Certificate obtention not valid, neither ACME or CA values were provided")
	}
}

// Obtain starts the async obtain request.
func (o *obtainer) ObtainACME(input ObtainInput) error {
	err := o.setPending(input)
	if err != nil {
		return err
	}
	config := input.User.NewConfig(input.CaDirURL)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		o.releasePending(input)
		return err
	}

	provider, err := newDNSControllerProvider(input.DNSCluster, input.DNSSettings, input.RequestName,
		input.TargetClass, input.IssuerName)
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

	go func() {
		var certificates *certificate.Resource
		var err error
		if input.RenewCert != nil {
			certificates, err = renew(client, input.RenewCert)
		} else {
			if input.CSR == nil {
				domains := append([]string{*input.CommonName}, input.DNSNames...)
				certificates, err = obtainForDomains(client, domains)
			} else {
				certificates, err = obtainForCSR(client, input.CSR)
			}
		}
		count := provider.GetChallengesCount()
		metrics.AddACMEObtain(input.IssuerName, err == nil, count, input.RenewCert != nil)
		output := &ObtainOutput{
			Certificates: certificates,
			IssuerInfo:   utils.NewACMEIssuerInfo(input.IssuerName),
			CommonName:   input.CommonName,
			DNSNames:     input.DNSNames,
			CSR:          input.CSR,
			Renew:        input.RenewCert != nil,
			Err:          err,
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

		if input.RenewCert != nil {
			certificates, err = renewCASignedCert(input.RenewCert, input.CAKeyPair)
		} else {
			if input.CSR == nil {
				certificates, err = newCASignedCertFromInput(input)
			}
		}
		output := &ObtainOutput{
			Certificates: certificates,
			IssuerInfo:   utils.NewCAIssuerInfo(input.IssuerName),
			CommonName:   input.CommonName,
			DNSNames:     input.DNSNames,
			CSR:          input.CSR,
			Renew:        input.RenewCert != nil,
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
		return append([]string{*input.CommonName}, input.DNSNames...), nil
	}
	cn, san, err := ExtractCommonNameAnDNSNames(input.CSR)
	if err != nil {
		return nil, err
	}
	return append([]string{*cn}, san...), nil
}

// CertificatesToSecretData converts a certificate resource to secret data.
func CertificatesToSecretData(certificates *certificate.Resource) map[string][]byte {
	data := map[string][]byte{}

	data[corev1.TLSCertKey] = certificates.Certificate
	data[corev1.TLSPrivateKeyKey] = certificates.PrivateKey
	data[TLSCAKey] = certificates.IssuerCertificate

	return data
}

// SecretDataToCertificates converts secret data to a certicate resource.
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
		return nil, fmt.Errorf("parsing certificate failed with %s", err.Error())
	}
	return cert, nil
}

// ExtractCommonNameAnDNSNames extracts values from a CSR (Certificate Signing Request).
func ExtractCommonNameAnDNSNames(csr []byte) (cn *string, san []string, err error) {
	certificateRequest, err := extractCertificateRequest(csr)
	if err != nil {
		err = fmt.Errorf("parsing CSR failed with: %s", err)
		return
	}
	cnvalue := certificateRequest.Subject.CommonName
	cn = &cnvalue
	san = certificateRequest.DNSNames[:]
	for _, ip := range certificateRequest.IPAddresses {
		san = append(san, ip.String())
	}
	return
}

// renewCASignedCert returns a new Certificate signed by a CA.
// An x509.CertificateRequest is created based on the info extracted from the existing PEM encoded CSR.
func renewCASignedCert(renewCert *certificate.Resource, CAKeyPair *TLSKeyPair) (*certificate.Resource, error) {
	crt, err := DecodeCertificate(renewCert.Certificate)
	if err != nil {
		return nil, err
	}
	csr := extractCertReqFromCert(crt)
	return newCASignedCertFromCertReq(csr, CAKeyPair)
}

// renewCASignedCert returns a new Certificate signed by a CA.
// An x509.CertificateRequest is created from scratch based on and ObtainInput object
func newCASignedCertFromInput(input ObtainInput) (*certificate.Resource, error) {
	csr, err := createCertReq(input)
	if err != nil {
		return nil, err
	}
	return newCASignedCertFromCertReq(csr, input.CAKeyPair)
}

// newCASignedCertFromCertReq returns a new Certificate signed by a CA based on
// an x509.CertificateRequest and a CA key pair. A private key will be generated.
func newCASignedCertFromCertReq(csr *x509.CertificateRequest, CAKeyPair *TLSKeyPair) (*certificate.Resource, error) {
	pubKeySize := pubKeySize(csr.PublicKey)
	if pubKeySize == 0 {
		pubKeySize = defaultKeySize(csr.PublicKeyAlgorithm)
	}
	privKey, privKeyPEM, err := generateKey(csr.PublicKeyAlgorithm, pubKeySize)
	if err != nil {
		return nil, err
	}
	return issueSignedCert(csr, false, privKey, privKeyPEM, CAKeyPair)
}

// RevokeCertificate revokes a certificate
func RevokeCertificate(user *RegistrationUser, caDirURL string, cert []byte) error {
	config := user.NewConfig(caDirURL)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return errors.Wrap(err, "client creation failed")
	}

	return client.Certificate.Revoke(cert)
}
