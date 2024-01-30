# Leighton-Micali Hash-Based Signatures

This repository contains implementations of [Leighton-Micali Hash-Based
Signatures (RFC 8554)](https://datatracker.ietf.org/doc/html/rfc8554).

## Security Notice

LMS signatures are stateful: Users must take care to never sign more than one
message with the same internal LM-OTS private key. To avoid catastrophe, state
must be maintained across multiple invocations of the signing algorithm.

When using our LMS implementations, the internal counter (`q`) will be
incremented before each signature is returned.

If the LMS private key is persisted to storage, you **MUST** update the
persistent storage after each signature is generated and before it is released
to the rest of the application. Failure to adhere to this requirement is a
security vulnerability in your application.

For a stateless hash-based signature algorithm, see
[SPHINCS+](https://sphincs.org).

NOTE: this project has not been externally audited, but the entire codebase 
was internally reviewed by cryptographers at Trail of Bits.

## Installation

```
go get https://github.com/trailofbits/lms-go
```

## Usage

```go
seckey    := lms.NewPrivateKey(common.LMS_SHA256_M32_H10, common.LMOTS_SHA256_N32_W4)
pubkey    := seckey.Public()
// The optional nil argument can be a user-chosen RNG
sig, err  := seckey.Sign([]byte("example"), nil)
sig_valid := pubkey.Verify([]byte("example"), sig)
```

### Key Management

We do not require much from the user in terms of key management. Any internal
state changing operation uses a call by pointer to update the internal state.
When persisting private keys to long term storage, users must be very careful
that **the same private key is never read from disk twice**. This would create
two private keys in the same state and thus when they are both used to sign a
message, the LMOTS private keys will have been reused, which is considered **not
good**.

## License

This codebase is licensed under the [3-Clause BSD License](https://opensource.org/license/bsd-3-clause/).

## Contribution

If you are interesting in contributing to this codebase, please see [CONTRIBUTING.md](/CONTRIBUTING.md) for more information.
