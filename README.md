# qssl

**Post-Quantum TLS. Patent-free. Formally verified.**

qssl is a pure Rust implementation of TLS with post-quantum cryptography. No OpenSSL dependency. No Java dependency. No Bouncy Castle. It runs natively on Linux, macOS, and anywhere Rust compiles.

---

## What It Does

| Capability | Detail |
|---|---|
| **Cipher suites** | 12 PQC suites: ML-KEM-1024, Falcon-1024, SPHINCS+-256s, ML-DSA-65/87 |
| **Modes** | Pure PQC and hybrid (classical + PQC) |
| **Formal proofs** | 100 Lean 4 theorems, zero sorries, Mathlib v4.27.0 |
| **Patents** | None. Patent-free by design. |
| **Dependencies** | Pure Rust. No OpenSSL, no JVM, no C bindings. |
| **Compliance targets** | NIST FIPS 203/204/205, CNSA 2.0, ANSSI hybrid requirements |

## The Problem qssl Solves

The PQC transition is fragmented by jurisdiction:

- **UK (NCSC) / USA (NSA)**: prefer pure PQC signatures
- **France (ANSSI) / Germany (BSI)**: require hybrid signatures (classical + PQC)
- **OpenSSL 3.5**: supports pure PQC but has zero support for composite/hybrid signatures
- **Bouncy Castle**: supports hybrid but is Java-only, doesn't integrate with Linux/C ecosystem

A business operating across these jurisdictions cannot get a single interoperable solution from existing tools.

qssl supports both modes natively. Pure PQC satisfies NCSC/NSA. Hybrid mode satisfies ANSSI/BSI. One library, no ecosystem split, no workarounds.

## Formal Verification

Every cryptographic property is proven in Lean 4:

- Key exchange correctness and forward secrecy
- Signature binding and non-repudiation
- Handshake protocol state machine invariants
- Cipher suite negotiation completeness

Published on Zenodo: [DOI 10.5281/zenodo.18663125](https://doi.org/10.5281/zenodo.18663125)

## Related Work

qssl is part of the Paraxiom post-quantum infrastructure stack:

| Project | Description | Theorems |
|---|---|---|
| [PQTG](https://doi.org/10.5281/zenodo.18786526) | PQ Transport Gateway for QKD control channels | 99 |
| qssh | PQ SSH replacement (Falcon, SPHINCS+, ML-KEM) | 67 |
| Drista | PQ encrypted chat (ML-KEM-1024, STARK, Nostr+IPFS) | 100 |
| QuantumHarmony | PQ L1 blockchain, live on 3 validators | 76 |
| Coherence Shield | AI trust proxy with toroidal logit bias | 115 |

Total: **909+ theorems** across 10 systems. All Lean 4, all zero sorries.

## Releases

Pre-built binaries are available under [Releases](https://github.com/Paraxiom/qssl/releases).

## Source Access

Source code is available under the [Paraxiom Source Collaboration License](LICENSE.md).

**We want to collaborate, not gatekeep.** If you're working on post-quantum infrastructure — whether in research, government, defence, or industry — reach out. We grant access to people who want to build together.

To request access:

1. Email **sylvain@paraxiom.org** with a brief description of your work
2. We'll set up a collaboration agreement (NDA if required by your context)
3. You get full source access to the private development repository

We say yes far more often than no.

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
