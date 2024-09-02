package istio_gateway

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	istionetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	istionetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	istionetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/gardener/cert-management/pkg/certman2/controller/source"
)

func createAddTestFunc[T client.Object](obj T) func() {
	return func() {
		var (
			gatewayPredicate predicate.Predicate
			gateway          T
			gatewayNew       T

			test func(T, T, types.GomegaMatcher, types.GomegaMatcher)
		)

		BeforeEach(func() {
			gatewayPredicate = Predicate(obj, source.DefaultClass)

			gateway = obj.DeepCopyObject().(T)
			gatewayNew = obj.DeepCopyObject().(T)

			test = func(
				gateway T,
				gatewayNew T,
				match types.GomegaMatcher,
				matchUpdate types.GomegaMatcher,
			) {
				Expect(gatewayPredicate.Create(event.CreateEvent{Object: gateway})).To(match)
				Expect(gatewayPredicate.Update(event.UpdateEvent{ObjectOld: gateway, ObjectNew: gatewayNew})).To(matchUpdate)
				Expect(gatewayPredicate.Delete(event.DeleteEvent{Object: gateway})).To(match)
				Expect(gatewayPredicate.Generic(event.GenericEvent{Object: gateway})).To(BeFalse())
			}
		})

		It("should handle nil objects as expected", func() {
			var zero T
			test(zero, zero, BeFalse(), BeFalse())
		})

		It("should handle unmanaged objects as expected", func() {
			test(gateway, gatewayNew, BeFalse(), BeFalse())
		})

		It("should handle gateway annotated as managed", func() {
			gateway.SetAnnotations(map[string]string{"cert.gardener.cloud/purpose": "managed"})
			gatewayNew.SetAnnotations(map[string]string{"cert.gardener.cloud/purpose": "managed"})
			test(gateway, gatewayNew, BeTrue(), BeTrue())
		})

		It("should handle services of wrong class as expected", func() {
			gateway.SetAnnotations(map[string]string{"cert.gardener.cloud/purpose": "managed", source.AnnotClass: "bar"})
			gatewayNew.SetAnnotations(map[string]string{"cert.gardener.cloud/purpose": "managed", source.AnnotClass: source.DefaultClass})
			test(gateway, gatewayNew, BeFalse(), BeTrue())
		})
	}
}

var _ = Describe("Add", func() {
	Describe("#Predicate", createAddTestFunc(&istionetworkingv1.Gateway{}))
	Describe("#Predicate-beta1", createAddTestFunc(&istionetworkingv1beta1.Gateway{}))
	Describe("#Predicate-alpha3", createAddTestFunc(&istionetworkingv1alpha3.Gateway{}))
})
