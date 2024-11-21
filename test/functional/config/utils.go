/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/gardener/controller-manager-library/pkg/resources"
	"github.com/gardener/controller-manager-library/pkg/utils"
	dnsapi "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	extensionsv1alpha "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/flow"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/retry"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/cert-management/pkg/apis/cert/v1alpha1"
	"github.com/gardener/cert-management/pkg/cert/legobridge"
)

const STATE_DELETED = "~DELETED~"

type TestUtils struct {
	AwaitTimeout  time.Duration
	PollingPeriod time.Duration
	Namespace     string
	Verbose       bool
	Client        client.Client
}

func init() {
	utils.Must(resources.Register(corev1.SchemeBuilder))
	utils.Must(resources.Register(apiextensionsv1.SchemeBuilder))
	utils.Must(resources.Register(v1alpha1.SchemeBuilder))
	utils.Must(resources.Register(extensionsv1alpha.SchemeBuilder))
	utils.Must(resources.Register(dnsapi.SchemeBuilder))
}

func CreateDefaultTestUtils() (*TestUtils, error) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return nil, fmt.Errorf("KUBECONFIG not set")
	}
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error loading kubeconfig from %s: %v\n", kubeconfig, err)
	}
	c, err := client.New(restConfig, client.Options{
		Scheme: resources.DefaultScheme(),
	})
	if err != nil {
		return nil, err
	}
	return &TestUtils{
		AwaitTimeout:  240 * time.Second,
		PollingPeriod: 200 * time.Millisecond,
		Namespace:     "default",
		Verbose:       true,
		Client:        c,
	}, nil
}

func (u *TestUtils) KubectlPlain(cmdline string) (string, error) {
	return u.runKubeCtl(cmdline)
}

func (u *TestUtils) KubectlGetAllIssuers() (string, error) {
	output, err := u.runKubeCtl("get issuer -oyaml")
	if err != nil {
		return "", err
	}
	return output, nil
}

func (u *TestUtils) KubectlGetAllCertificatesPlain() (string, error) {
	output, err := u.runKubeCtl("get cert -oyaml")
	if err != nil {
		return "", err
	}
	return output, nil
}

func (u *TestUtils) GetAllCertificates(ctx context.Context) (map[string]v1alpha1.Certificate, error) {
	list := &v1alpha1.CertificateList{}
	if err := u.Client.List(ctx, list); err != nil {
		return nil, err
	}
	certs := map[string]v1alpha1.Certificate{}
	for _, item := range list.Items {
		certs[item.Name] = item
	}
	return certs, nil
}

func (u *TestUtils) GetSecret(name string) (*corev1.Secret, error) {
	secret := &corev1.Secret{}
	err := u.Client.Get(context.Background(), client.ObjectKey{Namespace: u.Namespace, Name: name}, secret)
	return secret, err
}

func (u *TestUtils) CheckCertificatePrivateKey(secretName string, algorithm x509.PublicKeyAlgorithm, keySize int) error {
	secret, err := u.GetSecret(secretName)
	if err != nil {
		return err
	}
	cert, err := legobridge.DecodeCertificateFromSecretData(secret.Data)
	if err != nil {
		return err
	}
	if cert.PublicKeyAlgorithm != algorithm {
		return fmt.Errorf("algorithm mismatch: %s != %s", cert.PublicKeyAlgorithm, algorithm)
	}

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		size := pub.N.BitLen()
		if size != keySize {
			return fmt.Errorf("key size mismatch: %d != %d", size, keySize)
		}
	case *ecdsa.PublicKey:
		size := pub.Curve.Params().N.BitLen()
		if size != keySize {
			return fmt.Errorf("key size mismatch: %d != %d", size, keySize)
		}
	default:
		return fmt.Errorf("unknown public key")
	}
	return nil
}

func (u *TestUtils) KubectlApply(filename string) error {
	output, err := u.runKubeCtl(fmt.Sprintf("apply -f %q", filename))
	u.LogVerbose(output)
	return err
}

func (u *TestUtils) KubectlDelete(filename string) error {
	output, err := u.runKubeCtl(fmt.Sprintf("delete -f %q", filename))
	u.LogVerbose(output)
	return err
}

func (u *TestUtils) LogVerbose(output string) {
	if u.Verbose {
		println(output)
	}
}

func (u *TestUtils) runKubeCtl(cmdline string) (string, error) {
	return u.runCmd("kubectl -n " + u.Namespace + " " + cmdline)
}

func (u *TestUtils) runCmd(cmdline string) (string, error) {
	cmd := exec.Command("sh", "-c", cmdline)
	out, err := cmd.Output()
	if err != nil {
		println(string(err.(*exec.ExitError).Stderr))
		return string(out), fmt.Errorf("command `%s` failed: %w", cmdline, err)
	}
	return string(out), nil
}

func (u *TestUtils) WaitUntilIssuerReady(ctx context.Context, names ...string) error {
	return u.WaitUntilIssuerState(ctx, "Ready", names...)
}

func (u *TestUtils) WaitUntilIssuerDeleted(ctx context.Context, names ...string) error {
	return u.WaitUntilIssuerState(ctx, STATE_DELETED, names...)
}

func (u *TestUtils) WaitUntilCertReady(ctx context.Context, names ...string) error {
	return u.WaitUntilCertState(ctx, "Ready", names...)
}

func (u *TestUtils) WaitUntilCertError(ctx context.Context, names ...string) error {
	return u.WaitUntilCertState(ctx, "Error", names...)
}

func (u *TestUtils) WaitUntilCertDeleted(ctx context.Context, names ...string) error {
	return u.WaitUntilCertState(ctx, STATE_DELETED, names...)
}

func (u *TestUtils) WaitUntilCertRevoked(ctx context.Context, names ...string) error {
	return u.WaitUntilCertState(ctx, "Revoked", names...)
}

func (u *TestUtils) WaitUntilCertRevocationApplied(ctx context.Context, name string) error {
	return u.WaitUntilCertificateRevocationState(ctx, "Applied", name)
}

// WaitUntilCertState takes names of Certificates and waits for them to get ready with a timeout of 15 seconds.
func (u *TestUtils) WaitUntilCertState(ctx context.Context, expectedState string, names ...string) error {
	return waitUntil(ctx, u.Client, &v1alpha1.Certificate{}, func(obj *v1alpha1.Certificate) (bool, error) {
		if obj.Status.State != expectedState {
			return retry.MinorError(fmt.Errorf("Certificate %s has state %s != %s", obj.Name, obj.Status.State, expectedState))
		}
		return retry.Ok()

	}, u.AwaitTimeout, expectedState == STATE_DELETED, u.Namespace, names...)
}

// WaitUntilCertificateRevocationState takes names of CertificateRevocations and waits for them to get ready with a timeout of 15 seconds.
func (u *TestUtils) WaitUntilCertificateRevocationState(ctx context.Context, expectedState string, names ...string) error {
	return waitUntil(ctx, u.Client, &v1alpha1.CertificateRevocation{}, func(obj *v1alpha1.CertificateRevocation) (bool, error) {
		if obj.Status.State != expectedState {
			return retry.MinorError(fmt.Errorf("CertificateRevocation %s has state %s != %s", obj.Name, obj.Status.State, expectedState))
		}
		return retry.Ok()

	}, u.AwaitTimeout, expectedState == STATE_DELETED, u.Namespace, names...)
}

// WaitUntilIssuerState takes names of Issuer and waits for them to get ready with a timeout of 15 seconds.
func (u *TestUtils) WaitUntilIssuerState(ctx context.Context, expectedState string, names ...string) error {
	return waitUntil(ctx, u.Client, &v1alpha1.Issuer{}, func(obj *v1alpha1.Issuer) (bool, error) {
		if obj.Status.State != expectedState {
			return retry.MinorError(fmt.Errorf("Issuer %s has state %s != %s", obj.Name, obj.Status.State, expectedState))
		}
		return retry.Ok()

	}, u.AwaitTimeout, expectedState == STATE_DELETED, u.Namespace, names...)
}

func (u *TestUtils) WaitUntilCRDsReady(ctx context.Context, crds ...string) error {
	return waitUntil(ctx, u.Client, &apiextensionsv1.CustomResourceDefinition{}, func(obj *apiextensionsv1.CustomResourceDefinition) (bool, error) {
		if err := health.CheckCustomResourceDefinition(obj); err != nil {
			return retry.MinorError(err)
		}
		return retry.Ok()
	}, u.AwaitTimeout, false, u.Namespace, crds...)
}

// waitUntil takes names of objects and waits for them that the check method succeeds.
func waitUntil[T client.Object](ctx context.Context, c client.Client, t T, check func(t T) (bool, error), timeout time.Duration, ignoreNotFound bool, namespace string, names ...string) error {
	var fns []flow.TaskFn
	for _, name := range names {
		fns = append(fns, func(ctx context.Context) error {
			timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			return retry.Until(timeoutCtx, 1*time.Second, func(ctx context.Context) (done bool, err error) {
				obj := t.DeepCopyObject().(T)

				if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, obj); err != nil {
					if client.IgnoreNotFound(err) == nil {
						if ignoreNotFound {
							return retry.Ok()
						}
						return retry.MinorError(err)
					}
					return retry.SevereError(err)
				}

				return check(obj)
			})
		})
	}
	return flow.Parallel(fns...)(ctx)
}
