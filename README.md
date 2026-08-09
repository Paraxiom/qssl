# qssl

**Post-Quantum TLS. Patent-free. Pure Rust. Formally verified.**

qssl is a Rust implementation of TLS with post-quantum cryptography. No OpenSSL dependency. No Java dependency. No Bouncy Castle. It runs natively on Linux, macOS, and anywhere Rust compiles.

**Zero C.** Every cryptographic primitive is pure Rust, via [`paraxiom-pqc`](https://github.com/Paraxiom/paraxiom-pqc) — Paraxiom's from-scratch Rust implementation of the NIST post-quantum standards. No PQClean C, no `pqcrypto` FFI, no C bindings anywhere in the dependency graph. Protocol logic, state machines, and certificate handling are pure Rust too.

---

## What It Does

| Capability | Detail |
|---|---|
| **Cipher suites** | PQC suites over ML-KEM, Falcon, SPHINCS+ (SLH-DSA), and ML-DSA |
| **Modes** | Pure PQC and hybrid (classical + PQC) |
| **Crypto backend** | `paraxiom-pqc` — **pure Rust, zero C** |
| **Formal proofs** | Lean 4 + Mathlib, zero `sorry` |
| **Patents** | None. Patent-free by design. |
| **Compliance targets** | NIST FIPS 203/204/205, CNSA 2.0, ANSSI hybrid requirements |

## The Problem qssl Solves

The PQC transition is fragmented by jurisdiction:

- **UK (NCSC) / USA (NSA)**: prefer pure PQC signatures
- **France (ANSSI) / Germany (BSI)**: require hybrid signatures (classical + PQC)
- **OpenSSL 3.5**: supports pure PQC but has zero support for composite/hybrid signatures
- **Bouncy Castle**: supports hybrid but is Java-only, doesn't integrate with the Linux/C ecosystem

A business operating across these jurisdictions cannot get a single interoperable solution from existing tools.

qssl supports both modes natively. Pure PQC satisfies NCSC/NSA. Hybrid mode satisfies ANSSI/BSI. One library, no ecosystem split, no workarounds.

## Why Zero C Matters

The C-language cryptographic layer is where the memory-safety bug class lives — Heartbleed, the Debian OpenSSL flaw, and the long tail of buffer over-reads all originate in C crypto code. qssl removes that layer entirely: the sensitive cryptographic path is 100% memory-safe Rust, with no `unsafe` FFI into a C primitive.

A practical consequence: because there is no C in the tree, the whole codebase is analysable by pure-Rust tooling — including [Miri](https://github.com/rust-lang/miri), the Rust undefined-behaviour detector, which cannot run on projects that call into C. Earlier versions of qssl used the PQClean C reference implementations via `pqcrypto`; migrating to `paraxiom-pqc` closed that gap.

## Formal Verification

| Level | Tool | Scope |
|---|---|---|
| **Mathematical foundations** | Lean 4 + Mathlib | key exchange, signatures, protocol invariants — zero `sorry` |
| **Panic-free** | Kani (AWS) | harnesses across the Paraxiom stack |

Published on Zenodo: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

## Related Work

qssl is part of the Paraxiom post-quantum infrastructure stack:

| Project | Description |
|---|---|
| [PQTG](https://doi.org/10.5281/zenodo.18786526) | PQ Transport Gateway for QKD control channels |
| [qssh](https://github.com/Paraxiom/qssh) | PQ SSH replacement (Falcon, SPHINCS+, ML-KEM) |
| [paraxiom-pqc](https://github.com/Paraxiom/paraxiom-pqc) | The pure-Rust PQC core (ML-KEM, ML-DSA, SLH-DSA, Falcon) |
| QuantumHarmony | PQ Layer-1 blockchain |
| Coherence Shield | AI trust proxy + attestation |

## License

qssl is **dual-licensed**:

- **GNU General Public License v3.0** — use, study, modify and redistribute freely. Reciprocal: a product that incorporates qssl and is distributed to third parties must publish its source under GPL-3.0. Suits research, evaluation, and any product that is itself open.
- **Paraxiom commercial licence** — to embed qssl in a **proprietary** product without publishing your source. Lifts the GPL reciprocity requirement. Contact **sylvain@paraxiom.org**.

Releases published before 8 August 2026 were under different terms; the change is not retroactive.

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
