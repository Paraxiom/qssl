# qssl

**Post-Quantum TLS. Patent-free. Formally verified.**

qssl is a Rust implementation of TLS with post-quantum cryptography. No OpenSSL dependency. No Java dependency. No Bouncy Castle. It runs natively on Linux, macOS, and anywhere Rust compiles.

Cryptographic primitives use the [PQClean](https://github.com/PQClean/PQClean) C reference implementations via the [pqcrypto](https://github.com/rustpq/pqcrypto) Rust bindings. All protocol logic, state machines, and certificate handling is pure Rust.

---

## What It Does

| Capability | Detail |
|---|---|
| **Cipher suites** | 12 PQC suites: ML-KEM-1024, Falcon-1024, SPHINCS+-256s, ML-DSA-65/87 |
| **Modes** | Pure PQC and hybrid (classical + PQC) |
| **Formal proofs** | 100 Lean 4 theorems, zero sorries, Mathlib v4.27.0 |
| **Patents** | None. Patent-free by design. |
| **Dependencies** | Rust + PQClean C reference implementations. No OpenSSL, no JVM. |
| **Compliance targets** | NIST FIPS 203/204/205, CNSA 2.0, ANSSI hybrid requirements |

## The Problem qssl Solves

The PQC transition is fragmented by jurisdiction:

- **UK (NCSC) / USA (NSA)**: prefer pure PQC signatures
- **France (ANSSI) / Germany (BSI)**: require hybrid signatures (classical + PQC)
- **OpenSSL 3.5**: supports pure PQC but has zero support for composite/hybrid signatures
- **Bouncy Castle**: supports hybrid but is Java-only, doesn't integrate with Linux/C ecosystem

A business operating across these jurisdictions cannot get a single interoperable solution from existing tools.

qssl supports both modes natively. Pure PQC satisfies NCSC/NSA. Hybrid mode satisfies ANSSI/BSI. One library, no ecosystem split, no workarounds.

## Test Results

Tested on Linux x86_64 (Ubuntu 22.04, rustc 1.94.0), 2026-03-21.

### Cargo Test

```
test result: 52 passed; 1 failed; 0 ignored; 0 measured
```

| Result | Details |
|---|---|
| **52 passed** | All protocol, crypto, transport, and certificate tests |
| **1 failed** | `test_hybrid_kem` — ciphertext size validation off by 2 bytes ([#4](https://github.com/Paraxiom/qssl-src/issues/4)). Pure PQC mode unaffected. |

### Valgrind (Memory Safety)

```
valgrind --leak-check=full --error-exitcode=1
```

| Category | Bytes | Blocks | Source |
|---|---|---|---|
| Definitely lost | 5,400 | 27 | Upstream PQClean C code (SHAKE128 in Kyber768) |
| Possibly lost | 48 | 1 | Rust test harness overhead |
| **Paraxiom Rust code** | **0** | **0** | **No leaks in qssl code** |

All memory leaks trace to `PQCLEAN_KYBER768_CLEAN_kyber_shake128_absorb` in the upstream `fips202.c`. Filed as [#5](https://github.com/Paraxiom/qssl-src/issues/5). To be reported upstream to PQClean.

### Formal Verification

| Level | Tool | Scope |
|---|---|---|
| **Mathematical foundations** | Lean 4 + Mathlib v4.27.0 | 100 theorems — key exchange, signatures, protocol invariants |
| **Panic-free** | Kani (AWS) | 102 harnesses across the Paraxiom stack |

Published on Zenodo: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

### What We Cannot Test (and Why)

[Miri](https://github.com/rust-lang/miri) (Rust undefined behavior detector) cannot be used on this project because the PQClean cryptographic primitives are C code called via FFI. Miri only interprets pure Rust. This is a known Miri limitation, not a code deficiency. Valgrind covers the same ground for compiled binaries including the C layer.

## Related Work

qssl is part of the Paraxiom post-quantum infrastructure stack:

| Project | Description | Theorems |
|---|---|---|
| [PQTG](https://doi.org/10.5281/zenodo.18786526) | PQ Transport Gateway for QKD control channels | 99 |
| [qssh](https://github.com/Paraxiom/qssh) | PQ SSH replacement (Falcon, SPHINCS+, ML-KEM) | 67 |
| Drista | PQ encrypted chat (ML-KEM-1024, STARK, Nostr+IPFS) | 100 |
| QuantumHarmony | PQ L1 blockchain, live on 3 validators | 76 |
| Coherence Shield | AI trust proxy with toroidal logit bias | 115 |

Total: **909+ theorems** across 10 systems. All Lean 4, all zero sorries.

## Releases

Pre-built binaries are available under [Releases](https://github.com/Paraxiom/qssl/releases).

## Source Access

Source code is available under the [Paraxiom Source Collaboration License](LICENSE.md).

**We choose collaboration over extraction.** If you're working on post-quantum infrastructure — whether in research, government, defence, or industry — reach out. We grant access to people who want to build together.

To request access:

1. Email **sylvain@paraxiom.org** with a brief description of your work
2. We'll set up a collaboration agreement (NDA if required by your context)
3. You get full source access to the private development repository

That door opens when you knock.

## Why Not Fully Open Source?

We're a small team in Montreal building critical security infrastructure without external funding. Fully open-sourcing the implementation would allow well-resourced actors to take the work without contributing back.

Our formal proofs are public. Our binaries are public. Our research is published on Zenodo with DOIs. Everything is verifiable and auditable. The only thing behind the door is the implementation — and that door opens when you knock.

## Citation

```bibtex
@misc{cormier2025qssl,
  author    = {Cormier, Sylvain},
  title     = {qssl: Post-Quantum TLS with Formal Verification},
  year      = {2025},
  publisher = {Paraxiom Technologies Inc.},
  url       = {https://github.com/Paraxiom/qssl}
}
```

## Contact

**Sylvain Cormier**
Paraxiom Technologies Inc. — Montreal
sylvain@paraxiom.org | [paraxiom.org](https://paraxiom.org)
