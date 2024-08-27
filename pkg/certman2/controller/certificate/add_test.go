package certificate_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	. "github.com/gardener/cert-management/pkg/certman2/controller/certificate"
)

// TODO fix test / make it useful
var _ = Describe("Add", func() {
	Describe("#Predicate", func() {
		var (
			certificatePredicate predicate.Predicate
			cert                 *v1alpha1.Certificate
			certNew              *v1alpha1.Certificate

			test func(*v1alpha1.Certificate, *v1alpha1.Certificate, types.GomegaMatcher, types.GomegaMatcher)
		)

		BeforeEach(func() {
			certificatePredicate = Predicate()

			cert = &v1alpha1.Certificate{}
			certNew = &v1alpha1.Certificate{}

			test = func(
				cert *v1alpha1.Certificate,
				certNew *v1alpha1.Certificate,
				matchCreate types.GomegaMatcher,
				matchUpdate types.GomegaMatcher,
			) {
				Expect(certificatePredicate.Create(event.CreateEvent{Object: cert})).To(matchCreate)
				Expect(certificatePredicate.Update(event.UpdateEvent{ObjectOld: cert, ObjectNew: certNew})).To(matchUpdate)
				Expect(certificatePredicate.Delete(event.DeleteEvent{Object: cert})).To(BeFalse())
				Expect(certificatePredicate.Generic(event.GenericEvent{Object: cert})).To(BeFalse())
			}
		})

		It("should handle nil objects as expected", func() {
			test(nil, nil, BeFalse(), BeFalse())
		})

		It("should handle empty objects as expected", func() {
			Skip("TODO")
			test(cert, certNew, BeFalse(), BeFalse())
		})

		It("should handle objects with operation annotation as expected", func() {
			Skip("TODO")
			metav1.SetMetaDataAnnotation(&cert.ObjectMeta, "gardener.cloud/operation", "reconcile")
			metav1.SetMetaDataAnnotation(&certNew.ObjectMeta, "gardener.cloud/operation", "reconcile")

			test(cert, certNew, BeTrue(), BeTrue())
		})

		It("should handle the creation of objects with operation annotation as expected", func() {
			Skip("TODO")
			metav1.SetMetaDataAnnotation(&cert.ObjectMeta, "gardener.cloud/operation", "reconcile")

			test(cert, certNew, BeTrue(), BeFalse())
		})

		It("should handle objects whose last operation is not successful", func() {
			Skip("TODO")
			cert.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									State:       "Failed",
									Description: "Step B",
									Progress:    20,
								},
				*/}

			certNew.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									State:       "Progressing",
									Description: "Step A",
									Progress:    10,
								},
				*/}

			test(cert, certNew, BeTrue(), BeFalse())
		})

		It("should handle objects with a deletion timestamp as expected", func() {
			Skip("TODO")
			cert.SetDeletionTimestamp(&metav1.Time{})
			certNew.SetDeletionTimestamp(&metav1.Time{})

			test(cert, certNew, BeTrue(), BeTrue())
		})

		It("should not endlessly enqueue itself during deletion", func() {
			Skip("TODO")
			cert.SetDeletionTimestamp(&metav1.Time{})

			certNew = &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: &metav1.Time{},
				},
				Status: v1alpha1.CertificateStatus{
					/*					LastOperation: &gardencorev1beta1.LastOperation{
											Progress: 20,
										},
					*/},
			}

			test(cert, certNew, BeTrue(), BeFalse())
		})

		It("should not endlessly enqueue itself due to status updates", func() {
			Skip("TODO")
			cert.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									Description: "Step A",
									Progress:    10,
								},
				*/}

			certNew.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									Description: "Step B",
									Progress:    20,
								},
				*/}

			test(cert, certNew, BeTrue(), BeFalse())
		})
	})
})
