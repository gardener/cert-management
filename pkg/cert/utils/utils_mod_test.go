package utils_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/gardener/cert-management/pkg/cert/utils"
	"github.com/gardener/controller-manager-library/pkg/resources/abstract"
	libUtils "github.com/gardener/controller-manager-library/pkg/utils"
)

var _ = Describe("UtilsMod", func() {

	Describe("AssureStringSlice", func ()  {

		var mod *abstract.ModificationState
		BeforeEach(func ()  {
			mod = &abstract.ModificationState {
				ModificationState: libUtils.ModificationState{
					Modified: false,
				},
			}
		})

		It("should update the dst sclice with value if both slices have values", func ()  {
			dst := []string{"Old", "Value", "Another value"}
			value := []string{"New", "Value"}
			
			Expect(mod.Modified).To(BeFalse())

			utils.AssureStringSlice(mod, &dst, value)

			Expect(dst).To(Equal(value))
			Expect(mod.Modified).To(BeTrue())
		})

		It("should set dst to an empty slice if value is nil", func() {
            dst := []string{"Old", "Value"}

            utils.AssureStringSlice(mod, &dst, nil)

            Expect(dst).To(Equal([]string{}))
            Expect(mod.Modified).To(BeTrue())
        })

		It("should not modify dst if dst and value are equal", func ()  {
			dst := []string{"Value1", "Value2"}
			value := []string{"Value1", "Value2"}

            utils.AssureStringSlice(mod, &dst, value)

			Expect(dst).To(Equal(value))
            Expect(mod.Modified).To(BeFalse())
		})

	})

	Describe("EqualStringSlice", func() {
		It("should return true for equal slices", func() {
			Expect(utils.EqualStringSlice([]string{"a", "b", "c"}, []string{"a", "b", "c"})).To(BeTrue())
		})

		It("should return false for unequal slices", func() {
			Expect(utils.EqualStringSlice([]string{"a", "b", "c"}, []string{"a", "b", "d"})).To(BeFalse())
		})
	})
})
