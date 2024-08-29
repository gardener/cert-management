package ingress_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	networkingv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
	. "github.com/gardener/cert-management/pkg/certman2/controller/source/ingress"
)

var _ = Describe("Add", func() {
	Describe("#Predicate", func() {
		var (
			ingressPredicate predicate.Predicate
			ingress          *networkingv1.Ingress
			ingressNew       *networkingv1.Ingress

			test func(*networkingv1.Ingress, *networkingv1.Ingress, types.GomegaMatcher, types.GomegaMatcher)
		)

		BeforeEach(func() {
			ingressPredicate = Predicate(source.DefaultClass)

			ingress = &networkingv1.Ingress{}
			ingressNew = &networkingv1.Ingress{}

			test = func(
				ingress *networkingv1.Ingress,
				ingressNew *networkingv1.Ingress,
				match types.GomegaMatcher,
				matchUpdate types.GomegaMatcher,
			) {
				Expect(ingressPredicate.Create(event.CreateEvent{Object: ingress})).To(match)
				Expect(ingressPredicate.Update(event.UpdateEvent{ObjectOld: ingress, ObjectNew: ingressNew})).To(matchUpdate)
				Expect(ingressPredicate.Delete(event.DeleteEvent{Object: ingress})).To(match)
				Expect(ingressPredicate.Generic(event.GenericEvent{Object: ingress})).To(BeFalse())
			}
		})

		It("should handle nil objects as expected", func() {
			test(nil, nil, BeFalse(), BeFalse())
		})

		It("should handle unmanaged objects as expected", func() {
			test(ingress, ingressNew, BeFalse(), BeFalse())
		})

		It("should handle ingress annotated as managed", func() {
			ingress.Annotations = map[string]string{"cert.gardener.cloud/purpose": "managed"}
			ingressNew.Annotations = map[string]string{"cert.gardener.cloud/purpose": "managed"}
			test(ingress, ingressNew, BeTrue(), BeTrue())
		})

		It("should handle services of wrong class as expected", func() {
			ingress.Annotations = map[string]string{"cert.gardener.cloud/purpose": "managed"}
			ingress.Annotations[source.AnnotClass] = "bar"
			ingressNew.Annotations = map[string]string{"cert.gardener.cloud/purpose": "managed"}
			ingressNew.Annotations[source.AnnotClass] = source.DefaultClass
			test(ingress, ingressNew, BeFalse(), BeTrue())
		})
	})
})
