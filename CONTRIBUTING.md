Contributing to Trail of Bits LMS Go
=========================

Thank you for your interest in contributing to ToB `lms-go`!

The information below will help you set up a local development environment, as
well as performing common development tasks.

## Requirements

`lms-go`'s only development environment requirement *should* be a working
Go compiler. The library was developed under Go 1.21 so please use 1.21 or later
versions to ensure maximum compatibility.

## Development steps

First, clone this repository and ensure it builds:

```bash
$ git clone https://github.com/trailofbits/lms-go
$ cd lms-go
$ go build ./...
```

### Linting

First, [install `golangci-lint`](https://github.com/golangci/golangci-lint)
using your favorite method.

Use the following command to check rule files for formatting errors:

```bash
$ golangci-lint run
```

### Testing

You can run tests locally or re-run tests without using cached results with:

```bash
$ go test ./...
$ go test -count=1 ./...
```

To test a specific file:

```bash
$ go test ./path/to/file
```

### Development practices

All code is to be formatted with `go fmt` before merging.


### Documentation

Please provide enough documentation for any additional features that are added
to the code. Ideally, a code reviewer should be able to understand what a
complicated piece of code is supposed to do, and have a source for any specific
algorithm to check correctness.

### Releasing

**NOTE**: If you're a non-maintaining contributor, you don't need the steps
here! They're documented for completeness and for onboarding future maintainers.

We don't have a release cycle yet.
