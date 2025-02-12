# Cert-Management Test Design Document

This document contains:
- Guidelines and best practices for writing tests for the [Cert Management](https://github.com/gardener/cert-management) repository
- The types of tests used (Unit Tests, Integration Tests, Functional Tests)
- The setup and execution process for each type of test
- The purpose of each type of test

**Tests are a strict requirement.**
Furthermore, please follow the `Boy Scouts Rule`:
If you touch code for which either no tests exist or coverage is insufficient, then it is expected that **you will add relevant tests**.

This document is heavily based on the [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) document of the Gardener repository.
You can refer to that document for more information regarding best practices and debugging tests.

# Table of Contents

<!-- generated with "markdown-toc -i .\testing.md" -->

<!-- toc -->

- [General Information](#general-information)
- [Unit Tests](#unit-tests)
  * [Running Unit Tests](#running-unit-tests)
  * [Running Unit Tests with Coverage](#running-unit-tests-with-coverage)
  * [Show Coverage in IDE](#show-coverage-in-ide)
    + [VS Code](#vs-code)
  * [Debugging Unit Tests](#debugging-unit-tests)
  * [Mocking](#mocking)
  * [The Purpose of Unit Tests](#the-purpose-of-unit-tests)
  * [What should be covered?](#what-should-be-covered)
  * [What should not be covered?](#what-should-not-be-covered)
  * [Writing Unit Tests](#writing-unit-tests)
- [Integration Tests](#integration-tests)
  * [Running Integration Tests](#running-integration-tests)
  * [Set the KUBEBUILDER_ASSETS environment variable](#set-the-kubebuilder_assets-environment-variable)
    + [VS Code](#vs-code-1)
  * [Debugging Integration Tests](#debugging-integration-tests)
  * [The Purpose of Integration Tests](#the-purpose-of-integration-tests)
  * [What should be covered?](#what-should-be-covered-1)
  * [What should not be covered?](#what-should-not-be-covered-1)
  * [Writing integration tests](#writing-integration-tests)
- [Functional Tests](#functional-tests)
  * [Running Functional Tests](#running-functional-tests)
  * [The Purpose of Functional Tests](#the-purpose-of-functional-tests)
  * [What should be covered?](#what-should-be-covered-2)
  * [What should not be covered?](#what-should-not-be-covered-2)
  * [Writing integration tests](#writing-integration-tests-1)
- [Best Practices](#best-practices)
- [Further Information](#further-information)

<!-- tocstop -->

## General Information

- [Ginkgo](https://onsi.github.io/ginkgo/) is used as the testing framework paired with [Gomega](https://github.com/onsi/gomega) as the matcher library for all tests.
- We use [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest) for [integration tests](#integration-tests), as well as [pebble](https://github.com/letsencrypt/pebble) as a testing ACME Server.
- We conform to the general Gardener testing guidelines. Please read the chapter [Writing Tests (Relevant for All Kinds)](https://gardener.cloud/docs/gardener/testing/#writing-tests-relevant-for-all-kinds) in the Documentation.

## Unit Tests

### Running Unit Tests

```shell
make test
```

### Running Unit Tests with Coverage

```shell
make test-cov
```

This will create the machine-readable `./test.coverprofile` as well as a human-readable `test.coverage.html` file, which can be opened with a browser.

### Show Coverage in IDE

#### VS Code

You can show the coverage directly inside the VS Code editor in **two different ways**:

**First Way**

If not already done, you have to install the [Go Extension](https://marketplace.visualstudio.com/items?itemName=golang.Go).

On macOS, press `cmd + shift + p` (or on Windows, `ctrl + shift + p`) and select `Go: Toggle Test Coverage In Current Package`.
You have to do this every time the code changes.
This will only show the coverage inside the files of the current package.

**Second Way**

You can add the following entries to your `settings.json` file:

```json5
{
    // Other configurations
    "go.coverOnSave": true,
    "go.coverageDecorator": {
        "type": "gutter",
        "coveredHighlightColor": "rgba(64,128,128,0.5)",
        "uncoveredHighlightColor": "rgba(128,64,64,0.25)",
        "coveredGutterStyle": "blockgreen",
        "uncoveredGutterStyle": "blockred"
    },
    "go.coverOnSingleTest": true
}
```

This will automatically run all unit tests on save and display bars on the left side of the editor to visualize the covered lines of code.

[//]: <> (TODO: Add GoLand Documentation here)

### Debugging Unit Tests

You can debug the unit tests with similar methods displayed in the [Debugging Unit Tests](https://gardener.cloud/docs/gardener/testing/#debugging-unit-tests) section of the Gardener [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) document.

### Mocking

You can use [gomock](https://github.com/golang/mock) for easy mocking of interfaces.
The convention is to create a `mock` directory inside the package where the mocked interface is needed.

For example, the mock of an interface used in `project-root/pkg/cert/utils/utils_certificate.go` is now located inside the `project-root/pkg/cert/utils/mock/mocks.go` file.

```
project-root/
└── pkg/
    └── cert/
        └── utils/
            ├── utils_certificate.go
            └── mock
                ├── doc.go
                └── mocks.go
```

To create the mocks, you should create a `doc.go` file inside the mock directory.
This could look like this:

```go
// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -package=mock -destination=mocks.go github.com/gardener/controller-manager-library/pkg/resources Object

package mock
```

This uses `go:generate` to create the `mocks.go` file.
This is important, because that way the mocks automatically get (re)generated by running `make generate`.

Keep in mind to run `make generate` every time you change an interface that is mocked.

### The Purpose of Unit Tests

- Unit tests prove the correctness of a single unit according to the specification of its interface.
- Example units: functions, structs, predicates, event handlers.
- Unit tests should always be independent of one another.

### What should be covered?

- Unit tests have to cover **all important cases of input** and cover **edge cases**.
- While test coverage can be a good tool while writing tests, it is **not required to cover all lines of code**.
    - e.g., unit tests do not have to cover trivial functions like getter functions that only return a value.
- Furthermore, full line coverage does not necessarily mean that you have covered all cases of valid input.
- Very often it is not even possible to cover all cases of valid input.
- Always keep in mind to aim for complete coverage of **functionality, edge cases, and error cases** instead of focusing on line coverage.

### What should not be covered?

- **Large components**, e.g., entire controller `Reconcile` methods.
- If a component has multiple steps, think about **splitting it into smaller units**.
    - Then cover the units with the unit tests.
- Large components should rather be covered with [integration tests](#integration-tests) and [functional tests](#functional-tests).

### Writing Unit Tests

- It is preferred to test the external API of a module.
    - To ensure that you only test exposed functions, you should set the package of the test files to `{module_name}_test`.
- Internal functions can often be tested through the external API.
- If it is necessary to test internal functions, e.g., if it would be too complex to test them through the external API, you can set the package of the tests to the same as the module.

For more information regarding best practices while writing unit tests, have a look at the [Writing Unit Tests](https://gardener.cloud/docs/gardener/testing/#writing-unit-tests) chapter of the [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) document.

## Integration Tests

- We use [envtest](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest) for the integration tests.
- `envtest` provides you with a local control plane, ETCD, etc.
    - Keep in mind that `envtest` does **not provide full cluster functionality**.
    - e.g., there is no garbage collector.
- We use [pebble](https://github.com/letsencrypt/pebble) to test the functionality of the ACME issuer.
    - This provides a simplified ACME testing front end.
    - Some functionalities cannot be tested with the Pebble server because it does not provide all the features of the Let's Encrypt staging service.
        - e.g., Certificate Revocation cannot be performed with Pebble.
        - Please write [functional tests](#functional-tests) in these cases.

### Running Integration Tests

```shell
make test-integration
```

This will automatically set up everything you need for the integration tests.

### Set the KUBEBUILDER_ASSETS environment variable

If you want to execute or debug the integration tests **within your IDE instead of the terminal**, you have to set the `KUBEBUILDER_ASSETS` environment variable. 

Run the integration tests with the following command:

```shell
make test-integration | grep 'using envtest tools installed at'
```

This will give you the path to the local `envtest` installation:

```shell
using envtest tools installed at '/home/username/.local/share/kubebuilder-envtest/k8s/1.30.0-linux-amd64'
```

#### VS Code

You can set environment variables for Go tests inside the `settings.json` file.

Here you can add the environment variables inside the `go.testEnvVars` object.
With the example from above, the `settings.json` would look like this:

```json
{
    "go.testEnvVars": {
        "KUBEBUILDER_ASSETS": "/home/username/.local/share/kubebuilder-envtest/k8s/1.30.0-linux-amd64"
    }
}
```

[//]: <> (TODO: Add GoLand Documentation here)

### Debugging Integration Tests

You can debug the integration tests with similar methods shown in the [Debugging Integration Tests](https://gardener.cloud/docs/gardener/testing/#debugging-integration-tests) section of the Gardener [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) document.

### The Purpose of Integration Tests

- Integration tests prove that multiple units are correctly integrated into a fully-functional component of the system.
- They set up a full component (including used libraries) and run it against a test environment close to the actual setup.
    - That way it is possible to catch bugs that can only happen when running the controller against a real Kubernetes API.

### What should be covered?

- **Larger components**, especially the `Reconcile` methods of controllers.
- **Concrete use cases**, e.g., the creation of a certificate by an issuer.
- Generally, there should be **at least one integration test for every controller**.

### What should not be covered?

- Integration tests should **not cover every detailed test case**.
- They should, however, cover the **usual positive and negative cases** that will occur during normal operation.
- Generally, small units should rather be covered extensively in the [unit tests](#unit-tests) instead of integration tests.

### Writing integration tests

Generally, the same guidelines as stated in the [Writing Integration Tests](https://gardener.cloud/docs/gardener/testing/#writing-integration-tests) section of the [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) of the Gardener repository apply for the Cert-Management.

## Functional Tests

Instead of E2E tests, we use functional tests.
Similar to E2E tests, functional tests **run in a Kind Cluster under "real world" conditions**, e.g., they do communicate with the **Staging Service of Let's Encrypt**.
As opposed to E2E tests, functional tests test **single features and not the End-To-End usage**.
In the Cert-Management project, functional tests replace the classical E2E tests.

### Running Functional Tests

For the functional tests, use the test-e2e-local Make target by executing the following command:

```shell
make test-e2e-local
```

This will execute the following make targets:
- **kind-up**
    - Create the KIND cluster needed for the functional tests.
- **certman-up**
    - Set-Up the Cert-Manager.
- **test-functional-local**
    - Execute the functional tests.
- **certman-dnsrecords-up**
    - Build and deploy the cert-manager with DNS records configuration.
- **test-functional-local-dnsrecords**
    - Run functional tests with DNS records.

### The Purpose of Functional Tests

- Functional tests ensure that the **functional correctness of a feature** and that the feature **conforms to its specification**.
- They are supposed to catch bugs resulting from interaction between multiple components.
- Always test from the **perspective of the user**.
- The test cases should be as close as possible to the **real usage** of the user.

### What should be covered?

- **Every feature** should have functional tests to ensure that the feature meets its specification.
- Generally, functional tests should cover the "straight-forward-cases".
- Negative cases should be covered **if they are important to the user**.
- Functional tests should cover everything that **cannot be covered with integration tests**.
    - e.g., the revocation of a certificate because that is not supported by pebble.

### What should not be covered?

- **Small units**.
- **Details of the system**:
    - e.g., the user also wouldn’t expect that there is a kube-apiserver deployment in the seed; they rather expect that they can talk to it no matter how it is deployed.

### Writing integration tests

Generally, the same guidelines as stated in the [Writing e2e Tests](https://gardener.cloud/docs/gardener/testing/#writing-e2e-tests) section of the [Testing Strategy and Developer Guideline](https://gardener.cloud/docs/gardener/testing/) of the Gardener repository apply for the functional tests of the Cert-Management.

## Best Practices

Please read the chapter [Writing Tests (Relevant for All Kinds)](https://gardener.cloud/docs/gardener/testing/#writing-tests-relevant-for-all-kinds) of the Gardener Testing Strategy and Developer Guideline for information on best practices.

## Further Information

For more information regarding local development of this project, check out the [getting started guide](https://github.com/gardener/cert-management/blob/master/docs/development/getting-started.md).
