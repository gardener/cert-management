// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package ca

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	certmanclient "github.com/gardener/cert-management/pkg/certman2/client"
	"github.com/gardener/cert-management/pkg/certman2/core"
	"github.com/gardener/cert-management/pkg/shared/legobridge"
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
					},
				},
			},
		}

		err = fakeClient.Create(ctx, caIssuer)
		Expect(err).NotTo(HaveOccurred())

		certPEM, certPrivKeyPEM, err := newSelfSignedCertInPEMFormat()
		Expect(err).NotTo(HaveOccurred())
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

func newSelfSignedCertInPEMFormat() ([]byte, []byte, error) {
	input := legobridge.ObtainInput{
		CommonName: ptr.To("host.example.com"),
		DNSNames:   []string{"host2.example.com"},
		Duration:   ptr.To(time.Hour * 24 * 365),
		KeySpec:    legobridge.KeySpec{KeyType: legobridge.RSA2048},
		IsCA:       true,
	}
	return legobridge.NewSelfSignedCertInPEMFormat(input)
}
