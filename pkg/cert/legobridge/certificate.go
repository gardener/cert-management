/*
 * Copyright 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 *
 */

package legobridge

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/lego"
	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/controller-manager-library/pkg/logger"
	"github.com/gardener/controller-manager-library/pkg/resources"
)

const TLSCAKey = "ca.crt"

type ObtainerCallback func(output *ObtainOutput)

type ObtainInput struct {
	Logger      logger.LogContext
	User        *RegistrationUser
	DNSCluster  resources.Cluster
	DNSSettings DNSControllerSettings
	CaDirURL    string
	CommonName  *string
	DNSNames    []string
	CSR         []byte
	RequestName resources.ObjectName
	Callback    ObtainerCallback
	RenewCert   *certificate.Resource
}

type DNSControllerSettings struct {
	// Namespace to set for challenge DNSEntry
	Namespace string `json:"namespace,omitempty"`
	// OwnerId to set for challenge DNSEntry
	// +optional
	OwnerId *string `json:"owner,omitempty"`
}

type ObtainOutput struct {
	Certificates *certificate.Resource
	CommonName   *string
	DNSNames     []string
	CSR          []byte
	Renew        bool
	Err          error
}

func obtainForDomains(client *lego.Client, domains []string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}
	return client.Certificate.Obtain(request)
}

func obtainForCSR(client *lego.Client, csr []byte) (*certificate.Resource, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, fmt.Errorf("decoding CSR failed")
	}
	cert, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return client.Certificate.ObtainForCSR(*cert, true)
}

func renew(client *lego.Client, renewCert *certificate.Resource) (*certificate.Resource, error) {
	return client.Certificate.Renew(*renewCert, true, false)
}

func Obtain(input ObtainInput) error {
	config := input.User.NewConfig(input.CaDirURL)

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return err
	}

	provider, err := newDNSControllerProvider(input.Logger, input.DNSCluster, input.DNSSettings, input.RequestName)
	if err != nil {
		return err
	}
	nameservers := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}
	err = client.Challenge.SetDNS01Provider(provider, dns01.AddRecursiveNameservers(dns01.ParseNameservers(nameservers)))
	if err != nil {
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
		output := &ObtainOutput{certificates, input.CommonName, input.DNSNames, input.CSR, input.RenewCert != nil, err}
		input.Callback(output)
	}()

	return nil
}

func CertificatesToSecretData(certificates *certificate.Resource) map[string][]byte {
	data := map[string][]byte{}

	data[corev1.TLSCertKey] = certificates.Certificate
	data[corev1.TLSPrivateKeyKey] = certificates.PrivateKey
	data[TLSCAKey] = certificates.IssuerCertificate

	return data
}

func SecretDataToCertificates(data map[string][]byte) *certificate.Resource {
	certificates := &certificate.Resource{}
	certificates.Certificate = data[corev1.TLSCertKey]
	certificates.PrivateKey = data[corev1.TLSPrivateKeyKey]
	certificates.IssuerCertificate = data[TLSCAKey]
	return certificates
}

func DecodeCertificateFromSecretData(data map[string][]byte) (*x509.Certificate, error) {
	tlsCrt, ok := data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("fetching %s from request secret failed", corev1.TLSCertKey)
	}
	return DecodeCertificate(tlsCrt)
}

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

func ExtractCommonNameAnDNSNames(csr []byte) (cn *string, san []string, err error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		err = fmt.Errorf("decoding CSR pem failed")
		return
	}
	certificateRequest, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		err = fmt.Errorf("parsing CSR failed with: %s", err)
		return
	}
	cn = &certificateRequest.Subject.CommonName
	san = certificateRequest.DNSNames[:]
	for _, ip := range certificateRequest.IPAddresses {
		san = append(san, ip.String())
	}
	return
}
