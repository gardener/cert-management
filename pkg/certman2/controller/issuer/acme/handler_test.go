package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/core"
)

var _ = Describe("Handler", func() {
	var (
		ctx = context.Background()
		log = logr.Discard()

		fakeClient          client.Client
		acmeIssuerHandler   core.IssuerHandler
		support             *core.Support
		acmeIssuer          *v1alpha1.Issuer
		privateKeySecretRef = &corev1.SecretReference{
			Name:      "acme-secret",
			Namespace: "default",
		}
	)

	type wrappedRegistration struct {
		registration.Resource `json:",inline"`
		SecretHash            *string `json:"secretHash,omitempty"`
	}

	BeforeEach(func() {
		var err error
		fakeClient = fakeclient.NewClientBuilder().WithScheme(certmanclient.ClusterScheme).WithStatusSubresource(&v1alpha1.Issuer{}).Build()
		support, err = core.NewHandlerSupport("issuer-acme", "default", 100)
		Expect(err).NotTo(HaveOccurred())
		acmeIssuerHandler, err = NewACMEIssuerHandler(fakeClient, support, true)
		Expect(err).NotTo(HaveOccurred())

		acmeIssuer = &v1alpha1.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "issuer-acme",
				Namespace: "default",
			},
			Spec: v1alpha1.IssuerSpec{
				ACME: &v1alpha1.ACMESpec{
					Server:              "https://acme-staging-v02.api.letsencrypt.org/directory",
					Email:               "some.user@mydomain.com",
					PrivateKeySecretRef: privateKeySecretRef,
				},
			},
		}
		err = fakeClient.Create(ctx, acmeIssuer)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("#Reconcile", func() {
		Context("without existing private key secret", func() {
			It("should return error if autoRegistration is false", func() {
				acmeIssuer.Spec.ACME.AutoRegistration = false
				reconcileResult, err := acmeIssuerHandler.Reconcile(ctx, log, acmeIssuer)
				Expect(reconcileResult.IsZero()).To(BeTrue())
				Expect(err).To(HaveOccurred())
				err = fakeClient.Get(ctx, client.ObjectKeyFromObject(acmeIssuer), acmeIssuer)
				Expect(err).NotTo(HaveOccurred())
				Expect(acmeIssuer.Status.State).To(Equal("Error"))
			})
			When("autoRegistration is true", func() {
				BeforeEach(func() {
					acmeIssuer.Spec.ACME.AutoRegistration = true
				})
				It("should create a private key secret and Status.ACME should contain valid registration information", func() {
					reconcileResult, err := acmeIssuerHandler.Reconcile(ctx, log, acmeIssuer)
					Expect(reconcileResult.IsZero()).To(BeTrue())
					Expect(err).ToNot(HaveOccurred())
					secret := &corev1.Secret{}
					err = fakeClient.Get(ctx, core.ObjectKeyFromSecretReference(privateKeySecretRef), secret)
					Expect(err).NotTo(HaveOccurred())
					Expect(acmeIssuer.Status.State).To(Equal("Ready"))
					raw := acmeIssuer.Status.ACME // "body":{"contact":["mailto:some.user@mydomain.com"],"status":"valid"},"secretHash":"xxx","uri":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/xxx"
					wrappedReg := wrappedRegistration{}
					err = json.Unmarshal(raw.Raw, &wrappedReg)
					Expect(err).NotTo(HaveOccurred())
					Expect(wrappedReg.Resource.Body.Status).To(Equal("valid"))
					Expect(wrappedReg.Resource.Body.Contact[0]).To(Equal("mailto:some.user@mydomain.com"))
					Expect(wrappedReg.SecretHash).ToNot(BeNil())
					Expect(*wrappedReg.SecretHash).ToNot(Equal(""))
				})
			})
		})
		Context("with existing private key secret", func() {
			BeforeEach(func() {
				_, certPrivateKeyPEM, err := legobridge.GenerateKey(x509.ECDSA, 256)
				Expect(err).NotTo(HaveOccurred())
				secretData := map[string][]byte{"email": []byte("some.user@mydomain.com"), "privateKey": certPrivateKeyPEM}
				secret := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "acme-secret",
						Namespace: "default",
					},
					Data: secretData,
				}
				err = fakeClient.Create(ctx, &secret)
				Expect(err).NotTo(HaveOccurred())
			})
			It("should create a registration user and store registration in status.ACME", func() {
				reconcileResult, err := acmeIssuerHandler.Reconcile(ctx, log, acmeIssuer)
				Expect(reconcileResult.IsZero()).To(BeTrue())
				Expect(err).ToNot(HaveOccurred())
				Expect(acmeIssuer.Status.State).To(Equal("Ready"))
				raw := acmeIssuer.Status.ACME // "body":{"contact":["mailto:some.user@mydomain.com"],"status":"valid"},"secretHash":"xxx","uri":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/xxx"
				wrappedReg := wrappedRegistration{}
				err = json.Unmarshal(raw.Raw, &wrappedReg)
				Expect(err).ToNot(HaveOccurred())
				Expect(wrappedReg.Resource.Body.Status).To(Equal("valid"))
				Expect(wrappedReg.Resource.Body.Contact[0]).To(Equal("mailto:some.user@mydomain.com"))
				Expect(wrappedReg.SecretHash).ToNot(BeNil())
				Expect(*wrappedReg.SecretHash).ToNot(Equal(""))
			})
			It("should reuse existing registration", func() {
				// first reconcile
				reconcileResult, err := acmeIssuerHandler.Reconcile(ctx, log, acmeIssuer)
				Expect(reconcileResult.IsZero()).To(BeTrue())
				Expect(err).ToNot(HaveOccurred())
				Expect(acmeIssuer.Status.State).To(Equal("Ready"))
				raw := acmeIssuer.Status.ACME // "body":{"contact":["mailto:some.user@mydomain.com"],"status":"valid"},"secretHash":"xxx","uri":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/xxx"
				wrappedReg := wrappedRegistration{}
				err = json.Unmarshal(raw.Raw, &wrappedReg)
				Expect(err).ToNot(HaveOccurred())
				oldUri := wrappedReg.Resource.URI
				// second reconcile
				reconcileResult, err = acmeIssuerHandler.Reconcile(ctx, log, acmeIssuer)
				Expect(reconcileResult.IsZero()).To(BeTrue())
				Expect(err).ToNot(HaveOccurred())
				Expect(acmeIssuer.Status.State).To(Equal("Ready"))
				raw = acmeIssuer.Status.ACME // "body":{"contact":["mailto:some.user@mydomain.com"],"status":"valid"},"secretHash":"xxx","uri":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/xxx"
				wrappedReg = wrappedRegistration{}
				err = json.Unmarshal(raw.Raw, &wrappedReg)
				Expect(err).ToNot(HaveOccurred())
				newUri := wrappedReg.Resource.URI
				Expect(newUri).To(Equal(oldUri))
			})
		})
	})

	Describe("#Delete", func() {
		It("should return success if there are no errors", func() {
			now := metav1.Now()
			acmeIssuer.DeletionTimestamp = &now
			reconcileResult, err := acmeIssuerHandler.Delete(ctx, log, acmeIssuer)
			Expect(reconcileResult.IsZero()).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

func privateKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	block, err := pemBlockForKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(block), nil
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
