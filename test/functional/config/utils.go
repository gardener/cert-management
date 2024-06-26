/*
 * SPDX-FileCopyrightText: 2019 SAP SE or an SAP affiliate company and Gardener contributors
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/gardener/cert-management/pkg/cert/legobridge"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
)

const STATE_DELETED = "~DELETED~"

type TestUtils struct {
	AwaitTimeout  time.Duration
	PollingPeriod time.Duration
	Namespace     string
	Verbose       bool
}

func CreateDefaultTestUtils() *TestUtils {
	return &TestUtils{
		AwaitTimeout:  180 * time.Second,
		PollingPeriod: 200 * time.Millisecond,
		Namespace:     "default",
		Verbose:       true,
	}
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

func (u *TestUtils) KubectlGetAllCertificates() (map[string]interface{}, error) {
	output, err := u.runKubeCtl("get cert -o json")
	if err != nil {
		return nil, err
	}
	return u.toItemMap(output)
}

func (u *TestUtils) KubectlGetSecret(name string) (*corev1.Secret, error) {
	output, err := u.runKubeCtl("get secret " + name + " -o json")
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{}
	if err = json.Unmarshal([]byte(output), secret); err != nil {
		return nil, err
	}
	return secret, nil
}

func (u *TestUtils) CheckCertificatePrivateKey(secretName string, algorithm x509.PublicKeyAlgorithm, keySize int) error {
	secret, err := u.KubectlGetSecret(secretName)
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

func (u *TestUtils) toItemMap(output string) (map[string]interface{}, error) {
	untyped := map[string]interface{}{}
	err := json.Unmarshal([]byte(output), &untyped)
	if err != nil {
		return nil, err
	}

	if untyped["kind"] != "List" {
		return nil, fmt.Errorf("Result is not a list")
	}

	itemMap := map[string]interface{}{}
	items := untyped["items"].([]interface{})
	for _, rawItem := range items {
		item := rawItem.(map[string]interface{})
		name := item["metadata"].(map[string]interface{})["name"].(string)
		itemMap[name] = item
	}
	return itemMap, err
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

func (u *TestUtils) AwaitIssuerReady(names ...string) error {
	return u.AwaitState("issuer", "Ready", names...)
}

func (u *TestUtils) AwaitIssuerDeleted(names ...string) error {
	return u.AwaitState("issuer", STATE_DELETED, names...)
}

func (u *TestUtils) AwaitCertReady(names ...string) error {
	return u.AwaitState("cert", "Ready", names...)
}

func (u *TestUtils) AwaitCertError(names ...string) error {
	return u.AwaitState("cert", "Error", names...)
}

func (u *TestUtils) AwaitCertDeleted(names ...string) error {
	return u.AwaitState("cert", STATE_DELETED, names...)
}

func (u *TestUtils) AwaitCertRevoked(names ...string) error {
	return u.AwaitState("cert", "Revoked", names...)
}

func (u *TestUtils) AwaitCertRevocationApplied(name string) error {
	return u.AwaitState("certrevoke", "Applied", name)
}

func (u *TestUtils) AwaitState(resourceName, expectedState string, names ...string) error {
	msg := fmt.Sprintf("%s not %s: %v", resourceName, expectedState, names)
	return u.Await(msg, func() (bool, error) {
		output, err := u.runKubeCtl("get " + resourceName + " \"-o=jsonpath={range .items[*]}{.metadata.name}={.status.state}{'\\n'}{end}\"")
		if err != nil {
			return false, err
		}

		states := map[string]string{}
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			cols := strings.Split(line, "=")
			if len(cols) == 2 {
				states[cols[0]] = cols[1]
			}
		}
		for _, name := range names {
			if expectedState == STATE_DELETED {
				if _, ok := states[name]; ok {
					return false, nil
				}
			} else if states[name] != expectedState {
				return false, nil
			}
		}
		return true, nil
	})
}

type CheckFunc func() (bool, error)

func (u *TestUtils) Await(msg string, check CheckFunc) error {
	return u.AwaitWithTimeout(msg, check, u.AwaitTimeout)
}

func (u *TestUtils) AwaitWithTimeout(msg string, check CheckFunc, timeout time.Duration) error {
	var err error
	var ok bool

	limit := time.Now().Add(timeout)
	for time.Now().Before(limit) {
		ok, err = check()
		if ok {
			return nil
		}
		time.Sleep(u.PollingPeriod)
	}
	if err != nil {
		return fmt.Errorf("Timeout during check %s with error: %w", msg, err)
	}
	return fmt.Errorf("Timeout during check  %s", msg)
}

func (u *TestUtils) AwaitKubectlGetCRDs(crds ...string) error {
	var err error
	for _, crd := range crds {
		gomega.Eventually(func() error {
			_, err = u.runKubeCtl("get crd " + crd)
			return err
		}, u.AwaitTimeout, u.PollingPeriod).Should(gomega.BeNil())
		if err != nil {
			return err
		}
	}
	return err
}
