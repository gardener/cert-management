package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/go-logr/logr"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/cmd"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// The default values for the Pebble config have been taken from: https://github.com/letsencrypt/pebble/blob/main/test/config/pebble-config.json
const (
	listenAddress             = "localhost:14000"
	ocspResponderURL          = ""
	alternateRoots            = 0
	chainLength               = 1
	certificateValidityPeriod = 0
	httpPort                  = 5002
	tlsPort                   = 5001
	strict                    = true
	customResolverAddr        = ""
	requireEAB                = false
	retryAfterAuthz           = 3
	retryAfterOrder           = 5
)

// RunPebble runs a pebble server with the given configuration.
// The code is copied, shortened, and adapted from: https://github.com/letsencrypt/pebble/blob/main/cmd/pebble/main.go
func RunPebble(logr logr.Logger) (certificatePath, directoryAddress string, err error) {
	// We don't want to go through DNS-01 challenges in the integration tests as we would have to spin up a local, authoritative DNS server.
	// Setting the environment variable PEBBLE_VA_ALWAYS_VALID to 1 makes the Pebble server always return a valid response for the validation authority.
	// Testing the DNS-01 challenge is covered by the functional E2E tests.
	// See the Pebble documentation: https://github.com/letsencrypt/pebble#skipping-validation
	err = os.Setenv("PEBBLE_VA_ALWAYS_VALID", "1")
	if err != nil {
		return "", "", fmt.Errorf("failed to set environment variable: %v", err)
	}

	certificatePath, privateKeyPath, err := generateCertificate()
	if err != nil {
		return "", "", err
	}

	log := NewLogBridge(logr)

	database := db.NewMemoryStore()
	certificateAuthority := ca.New(log, database, ocspResponderURL, alternateRoots, chainLength, certificateValidityPeriod)
	validationAuthority := va.New(log, httpPort, tlsPort, strict, customResolverAddr, database)

	wfeImpl := wfe.New(log, database, validationAuthority, certificateAuthority, strict, requireEAB, retryAfterAuthz, retryAfterOrder)
	muxHandler := wfeImpl.Handler()

	directoryAddress = fmt.Sprintf("https://%s%s", listenAddress, wfe.DirectoryPath)

	log.Printf("Listening on: %s", listenAddress)
	log.Printf("ACME directory available at: %s",
		directoryAddress)

	go func() {
		err := http.ListenAndServeTLS(
			listenAddress,
			certificatePath,
			privateKeyPath,
			muxHandler)
		cmd.FailOnError(err, "Calling ListenAndServeTLS()")
	}()

	return certificatePath, directoryAddress, nil
}

// CheckPebbleAvailability checks if the Pebble ACME server is available at the given address.
func CheckPebbleAvailability(certificatePath string, listenAddress string) error {
	rootCAs, err := loadCertPool(certificatePath)
	if err != nil {
		return err
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS13}
	http.DefaultTransport = customTransport
	client := &http.Client{Transport: customTransport}

	response, err := client.Get(listenAddress)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status 200 from %s, got %d", listenAddress, response.StatusCode)
	}

	return nil
}

// generateCertificate generates a certificate and private key for the Pebble server in a temporary OS directory.
// Inspired from: https://github.com/gardener/cert-management/blob/584014befb02a80a063184c9b765db7e12e66f52/hack/kind/pebble/pebble-up.sh#L15-L23
func generateCertificate() (certificatePath, privateKeyPath string, err error) {
	tempDirectoryPath, err := os.MkdirTemp("", "pebble")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temporary directory: %v", err)
	}

	goRoot := runtime.GOROOT()
	goFile := fmt.Sprintf("%s/src/crypto/tls/generate_cert.go", goRoot)
	command := exec.Command("go", "run", goFile, "--host=localhost", "--ecdsa-curve=P256")
	command.Dir = tempDirectoryPath
	err = command.Run()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate certificate: %v", err)
	}

	certificatePath = fmt.Sprintf("%s/cert.pem", tempDirectoryPath)
	privateKeyPath = fmt.Sprintf("%s/key.pem", tempDirectoryPath)

	return certificatePath, privateKeyPath, nil
}

func loadCertPool(certificatePath string) (*x509.CertPool, error) {
	certData, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certData)
	if !ok {
		return nil, fmt.Errorf("failed to parse certificates from PEM")
	}

	return certPool, nil
}
