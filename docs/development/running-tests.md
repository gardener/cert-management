# Running Tests

## Running Unit Tests

```shell
make test
```

## Running Integration Tests

```shell
make test-integration
```

### Debugging Integration Tests

Run the integration tests once to set up the [`envtest`](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest) tools on your local machine:

```shell
make test-integration | grep 'using envtest tools installed at'
```

The output should look similar to the following (on macOS):

```shell
using envtest tools installed at '/Users/d022915/Library/Application Support/io.kubebuilder.envtest/k8s/1.30.0-darwin-arm64'
```

Copy the path of your local `envtest` installation.
In your IDE set the `KUBEBUILDER_ASSETS` environment variable to the path that you copied.
Finally, run or debug the integration tests in your IDE as you usually would.

## Running E2E Tests

```shell
make test-e2e
```