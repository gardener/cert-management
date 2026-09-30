// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cainjector

import (
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// HasInjectAnnotationPredicate filters objects that carry an inject-ca-from* annotation.
func HasInjectAnnotationPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		ann := obj.GetAnnotations()
		_, hasCert := ann[AnnotationInjectCAFrom]
		_, hasSecret := ann[AnnotationInjectCAFromSecret]
		return hasCert || hasSecret
	})
}
