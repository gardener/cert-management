package certificate_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/apis/cert/v1alpha1"
	. "github.com/gardener/cert-management/pkg/certman2/controller/issuer"
)

// TODO fix test / make it useful
var _ = Describe("Add", func() {
	Describe("#Predicate", func() {
		var (
			issuerPredicate predicate.Predicate
			issuer          *v1alpha1.Certificate
			issuerNew       *v1alpha1.Certificate

			test func(*v1alpha1.Certificate, *v1alpha1.Certificate, types.GomegaMatcher, types.GomegaMatcher)
		)

		BeforeEach(func() {
			issuerPredicate = Predicate()

			issuer = &v1alpha1.Certificate{}
			issuerNew = &v1alpha1.Certificate{}

			test = func(
				issuer *v1alpha1.Certificate,
				issuerNew *v1alpha1.Certificate,
				matchCreate types.GomegaMatcher,
				matchUpdate types.GomegaMatcher,
			) {
				Expect(issuerPredicate.Create(event.CreateEvent{Object: issuer})).To(matchCreate)
				Expect(issuerPredicate.Update(event.UpdateEvent{ObjectOld: issuer, ObjectNew: issuerNew})).To(matchUpdate)
				Expect(issuerPredicate.Delete(event.DeleteEvent{Object: issuer})).To(BeFalse())
				Expect(issuerPredicate.Generic(event.GenericEvent{Object: issuer})).To(BeFalse())
			}
		})

		It("should handle nil objects as expected", func() {
			test(nil, nil, BeFalse(), BeFalse())
		})

		It("should handle empty objects as expected", func() {
			test(issuer, issuerNew, BeFalse(), BeFalse())
		})

		It("should handle objects with operation annotation as expected", func() {
			metav1.SetMetaDataAnnotation(&issuer.ObjectMeta, "gardener.cloud/operation", "reconcile")
			metav1.SetMetaDataAnnotation(&issuerNew.ObjectMeta, "gardener.cloud/operation", "reconcile")

			test(issuer, issuerNew, BeTrue(), BeTrue())
		})

		It("should handle the creation of objects with operation annotation as expected", func() {
			metav1.SetMetaDataAnnotation(&issuer.ObjectMeta, "gardener.cloud/operation", "reconcile")

			test(issuer, issuerNew, BeTrue(), BeFalse())
		})

		It("should handle objects whose last operation is not successful", func() {
			issuer.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									State:       "Failed",
									Description: "Step B",
									Progress:    20,
								},
				*/}

			issuerNew.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									State:       "Progressing",
									Description: "Step A",
									Progress:    10,
								},
				*/}

			test(issuer, issuerNew, BeTrue(), BeFalse())
		})

		It("should handle objects with a deletion timestamp as expected", func() {
			issuer.SetDeletionTimestamp(&metav1.Time{})
			issuerNew.SetDeletionTimestamp(&metav1.Time{})

			test(issuer, issuerNew, BeTrue(), BeTrue())
		})

		It("should not endlessly enqueue itself during deletion", func() {
			issuer.SetDeletionTimestamp(&metav1.Time{})

			issuerNew = &v1alpha1.Certificate{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: &metav1.Time{},
				},
				Status: v1alpha1.CertificateStatus{
					/*					LastOperation: &gardencorev1beta1.LastOperation{
											Progress: 20,
										},
					*/},
			}

			test(issuer, issuerNew, BeTrue(), BeFalse())
		})

		It("should not endlessly enqueue itself due to status updates", func() {
			issuer.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									Description: "Step A",
									Progress:    10,
								},
				*/}

			issuerNew.Status = v1alpha1.CertificateStatus{
				/*				LastOperation: &gardencorev1beta1.LastOperation{
									Description: "Step B",
									Progress:    20,
								},
				*/}

			test(issuer, issuerNew, BeTrue(), BeFalse())
		})
	})
})
