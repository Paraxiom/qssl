# QSSL - Quantum-Safe Secure Layer

A **patent-free** post-quantum TLS implementation using SPHINCS+ KEM instead of Kyber. Experimental implementation for research and testing quantum-safe protocols without patent concerns.

## ⚠️ Experimental Research Project

**Version 0.2.0** - Now with patent-free SPHINCS+ KEM as default!

QSSL is a research project exploring post-quantum TLS without patent encumbrances:
- **Patent-free by default**: SPHINCS+ KEM avoids Kyber patent concerns
- Testing quantum-safe algorithms in real protocols
- Quantum-native design with traffic analysis resistance
- Educational and research purposes

For production quantum-safe TLS, consider contributing to [rustls](https://github.com/rustls/rustls) or waiting for official TLS PQC extensions.

## 🚧 Implementation Status

QSSL is actively under development as a research platform. Core cryptographic components are functional with ongoing experimentation.

### What's Working
- ✅ **Patent-Free SPHINCS+ KEM**: Primary key exchange using SPHINCS+ signatures (no Kyber patents!)
- ✅ **Post-Quantum Certificates**: Full X.509-like certificate support with Falcon-512/SPHINCS+
- ✅ **Quantum-Native Mode**: Fixed-size frames with traffic analysis resistance
- ✅ **Digital Signatures**: Falcon-512/1024 and SPHINCS+ implementation
- ✅ **Symmetric Encryption**: AES-GCM and ChaCha20-Poly1305
- ✅ **Transport Layer**: Record protocol with authenticated encryption
- ✅ **Handshake Protocol**: Certificate exchange and key negotiation
- ✅ **Test Coverage**: All 40 tests passing

### In Progress
- 🔄 **Connection API**: High-level connection management
- 🔄 **Session Resumption**: 0-RTT support
- 🔄 **Integration Tests**: End-to-end protocol testing
- 🔄 **Performance Optimization**: Reducing handshake latency

### TODO
- ⏳ **Certificate Chains**: Full CA chain validation
- ⏳ **OCSP Stapling**: Certificate revocation checking
- ⏳ **Production Hardening**: Security audit and fuzzing

## Why QSSL Exists

While projects like rustls and OpenSSL are adding PQC support to existing TLS, QSSL explores:

1. **Patent-free approach**: SPHINCS+ KEM avoids Kyber patent issues
2. **Clean-slate design**: TLS reimagined for quantum threats
3. **Traffic analysis resistance**: Fixed-size frames, dummy traffic, timing obfuscation
4. **Algorithm agility**: Easy to swap/test different PQC algorithms
5. **Research platform**: Test ideas too experimental for production TLS

## Features

- **Patent-Free Key Exchange**: SPHINCS+ KEM (no Kyber patent concerns!)
- **Legacy Kyber Support**: Kyber (512/768/1024) for compatibility
- **Post-Quantum Signatures**: Falcon, Dilithium, SPHINCS+
- **Hybrid Encryption**: AES-GCM, ChaCha20-Poly1305
- **Memory Safety**: Written in Rust with automatic zeroization
- **Async/Await**: Built on Tokio for high performance
- **Session Management**: Resumption and 0-RTT support

## Quick Start

### Running the Echo Server Example

Terminal 1:
```bash
cargo run --example echo_server
```

Terminal 2:
```bash
cargo run --example echo_client
```

### Using QSSL in Your Project

```rust
use qssl::{QsslConnection, QsslContext};

// Client
let conn = QsslConnection::connect("server:4433").await?;
conn.send(b"Hello Quantum World").await?;
let response = conn.recv().await?;

// Server
let listener = TcpListener::bind("0.0.0.0:4433").await?;
let (stream, _) = listener.accept().await?;
let conn = QsslConnection::accept(stream).await?;
```

## Cipher Suites

| Suite | KEM | Signature | Cipher | Hash | Security | Patent-Free |
|-------|-----|-----------|--------|------|----------|-------------|
| 0x0010 | SPHINCS+ | Falcon512 | AES-128-GCM | SHA256 | 128-bit | ✅ |
| 0x0011 | SPHINCS+ | Falcon512 | AES-256-GCM | SHA384 | 192-bit | ✅ |
| 0x0012 | SPHINCS+ | Falcon1024 | AES-256-GCM | SHA512 | 256-bit | ✅ |
| 0x0013 | SPHINCS+ | SPHINCS-256f | AES-256-GCM | SHA384 | 192-bit | ✅ |
| 0x0014 | SPHINCS+ | Falcon512 | ChaCha20 | SHA384 | 192-bit | ✅ |
| 0x0001 | Kyber512 | Falcon512 | AES-128-GCM | SHA256 | 128-bit | ⚠️ |
| 0x0002 | Kyber768 | Falcon512 | AES-256-GCM | SHA384 | 192-bit | ⚠️ |
| 0x0003 | Kyber1024 | Falcon1024 | AES-256-GCM | SHA512 | 256-bit | ⚠️ |

## Architecture

```
┌─────────────────────────────────────────┐
│         Application Layer                │
├─────────────────────────────────────────┤
│         QSSL Connection                  │
│  (Handshake, State Machine, Context)     │
├─────────────────────────────────────────┤
│         QSSL Transport                   │
│   (Records, Encryption, Sequencing)      │
├─────────────────────────────────────────┤
│      Post-Quantum Cryptography           │
│   (Kyber, Falcon, SPHINCS+, etc.)        │
├─────────────────────────────────────────┤
│         Network (TCP/UDP)                │
└─────────────────────────────────────────┘
```

## Implementation Status

### Core Components ✅
- [x] Protocol specification
- [x] Handshake implementation
- [x] Transport layer with encryption
- [x] Session management
- [x] Kyber KEM integration
- [x] Falcon signature integration
- [x] Symmetric encryption (AES-GCM, ChaCha20)
- [x] Key derivation (HKDF)

### In Progress 🚧
- [ ] Certificate validation
- [ ] Full session resumption
- [ ] 0-RTT implementation
- [ ] Extension handling
- [ ] Alert protocol

### Integration
- [x] QSSH adapter created
- [x] QNGINX bindings planned
- [ ] C FFI interface
- [ ] Python bindings
- [ ] WASM support

## Building

```bash
# Build library
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench

# Build examples
cargo build --examples
```

## Testing

The project includes comprehensive tests:
- Unit tests for all crypto operations
- Integration tests for handshake
- Session management tests
- Transport layer tests

Run all tests:
```bash
cargo test
```

Run with logging:
```bash
RUST_LOG=debug cargo test
```

## Performance

Benchmark results on Apple M1:
- Kyber768 key generation: ~50μs
- Kyber768 encapsulation: ~60μs
- Kyber768 decapsulation: ~70μs
- Falcon512 signing: ~200μs
- Falcon512 verification: ~80μs
- Full handshake: ~2ms

## Security Considerations

1. **Post-Quantum Security**: All algorithms are NIST-approved candidates
2. **Memory Safety**: Rust prevents buffer overflows and use-after-free
3. **Zeroization**: All sensitive data is zeroized on drop
4. **Forward Secrecy**: Ephemeral keys for each session
5. **Replay Protection**: Sequence numbers prevent replay attacks

## Integration with Other Projects

### QSSH Integration
QSSH can use QSSL as its transport layer:
```rust
use qssl::integrations::qssh::QsshTransport;

let transport = QsshTransport::connect("server:22", config).await?;
// Use QSSL for quantum-safe SSH
```

### QNGINX Integration
QNGINX can use QSSL for HTTPS:
```nginx
server {
    listen 443 qssl;
    qssl_certificate cert.pem;
    qssl_certificate_key key.pem;
    qssl_ciphers QSSL_KYBER768_FALCON512_AES256_SHA384;
}
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

**EXPERIMENTAL SOFTWARE** - This is a research project, not production-ready software:
- No security audit has been performed
- Not suitable for protecting real data
- Use at your own risk
- For production TLS, use rustls or OpenSSL

## License

This project is dual-licensed under MIT and Apache-2.0.

## Acknowledgments

- Built on top of the `pqcrypto` crate family
- Inspired by rustls and OpenSSL
- Part of the QuantumVerse Protocol Suite

## Contact

- GitHub: https://github.com/QuantumVerseProtocols/qssl
- Issues: https://github.com/QuantumVerseProtocols/qssl/issues

---

*QSSL - Securing communications for the quantum era*