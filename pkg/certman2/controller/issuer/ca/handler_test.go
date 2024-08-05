package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/core"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"

	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var _ = Describe("Handler", func() {
	var (
		ctx = context.Background()
		log = logr.Discard()

		fakeClient      client.Client
		caIssuerHandler core.IssuerHandler
		support         *core.Support
		caIssuer        *v1alpha1.Issuer
	)

	BeforeEach(func() {
		var err error
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).WithStatusSubresource(&v1alpha1.Issuer{}).Build()
		support, err = core.NewHandlerSupport("issuer-ca", "default", 100)
		Expect(err).NotTo(HaveOccurred())
		caIssuerHandler, err = NewCAIssuerHandler(fakeClient, support, true)
		Expect(err).NotTo(HaveOccurred())

		caIssuer = &v1alpha1.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "issuer-ca",
				Namespace: "default",
			},
			Spec: v1alpha1.IssuerSpec{
				CA: &v1alpha1.CASpec{
					PrivateKeySecretRef: &corev1.SecretReference{
						Name:      "issuer-ca-secret",
						Namespace: "default",
					}},
			},
		}

		err = fakeClient.Create(ctx, caIssuer)
		Expect(err).NotTo(HaveOccurred())

		certPEM, certPrivKeyPEM, err := newSelfSignedCertInPEMFormat(x509.RSA, 2048)
		secretData := map[string][]byte{"tls.crt": certPEM, "tls.key": certPrivKeyPEM}
		secret := corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "issuer-ca-secret",
				Namespace: "default",
			},
			Data: secretData,
			Type: "kubernetes.io/tls",
		}
		err = fakeClient.Create(ctx, &secret)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("#Reconcile", func() {
		It("should return success if there are no errors", func() {
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			err = fakeClient.Get(ctx, client.ObjectKeyFromObject(caIssuer), caIssuer)
			Expect(err).NotTo(HaveOccurred())
			Expect(caIssuer.Status.State).To(Equal("Ready"))
			Expect(*caIssuer.Status.Type).To(Equal("ca"))
		})
		It("should return error if secret not existing", func() {
			caIssuer.Spec.CA.PrivateKeySecretRef.Name = "foo"
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).To(HaveOccurred())
			Expect(caIssuer.Status.State).To(Equal("Error"))
		})
	})
	Describe("#Delete", func() {
		It("should return success if there are no errors", func() {
			reconcileResult, err := caIssuerHandler.Reconcile(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
			now := metav1.Now()
			caIssuer.DeletionTimestamp = &now
			reconcileResult, err = caIssuerHandler.Delete(ctx, log, caIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

// TODO replace with existing method if SelfSigned certificate feature is merged: https://github.com/gardener/cert-management/pull/228
func newSelfSignedCertInPEMFormat(algo x509.PublicKeyAlgorithm, algoSize int) ([]byte, []byte, error) {
	certPrivateKey, certPrivateKeyPEM, err := generateKey(algo, algoSize)
	if err != nil {
		return nil, nil, err
	}
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	if algo == x509.RSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "host.example.com",
		},
		DNSNames:              []string{"host2.example.com"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
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

// TODO replace with existing method if SelfSigned certificate feature is merged
func generateKey(algo x509.PublicKeyAlgorithm, size int) (crypto.Signer, []byte, error) {
	// RSAMinSize is the minimum size for an RSA key
	const (
		RSAMinSize int = 2048
		RSAMaxSize int = 8192
		ECCurve256 int = 256
		ECCurve384 int = 384
		ECCurve521 int = 521
	)

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

// TODO replace with existing method if SelfSigned certificate feature is merged
func privateKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	block, err := pemBlockForKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
}

// TODO replace with existing method if SelfSigned certificate feature is merged
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
