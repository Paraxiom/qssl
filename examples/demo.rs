//! QSSL Demonstration
//!
//! This example shows how to use QSSL for quantum-safe communications

use qssl::{QsslConnection, QsslContext, QsslResult};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() -> QsslResult<()> {
    // Initialize QSSL
    qssl::init()?;

    println!("=== QSSL Quantum-Safe Communication Demo ===\n");
    println!("Version: {}", qssl::version());
    println!("Protocol: 0x{:04X}\n", qssl::protocol_version());

    // Demo selection
    let demo = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "client".to_string());

    match demo.as_str() {
        "server" => run_server().await?,
        "client" => run_client().await?,
        "benchmark" => run_benchmark().await?,
        _ => println!("Usage: cargo run --example demo [server|client|benchmark]"),
    }

    Ok(())
}

/// Run QSSL server
async fn run_server() -> QsslResult<()> {
    println!("Starting QSSL Server on 0.0.0.0:4433...\n");

    let listener = TcpListener::bind("0.0.0.0:4433").await?;
    println!("Server listening... waiting for connections");

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("Connection from: {}", addr);

        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("Client error: {}", e);
            }
        });
    }
}

/// Handle client connection
async fn handle_client(stream: tokio::net::TcpStream) -> QsslResult<()> {
    println!("Performing QSSL handshake...");

    // Accept QSSL connection
    let conn = QsslConnection::accept(stream).await?;

    println!("✓ Handshake complete!");
    if let Some(suite) = conn.cipher_suite() {
        println!("  Cipher Suite: {:?}", suite);
    }

    // Echo server
    loop {
        match conn.recv().await {
            Ok(data) => {
                let msg = String::from_utf8_lossy(&data);
                println!("Received: {}", msg);

                // Echo back
                conn.send(&data).await?;

                if msg.trim() == "quit" {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    conn.close().await?;
    println!("Client disconnected");

    Ok(())
}

/// Run QSSL client
async fn run_client() -> QsslResult<()> {
    println!("Connecting to QSSL Server at localhost:4433...\n");

    // Connect to server
    let conn = QsslConnection::connect("localhost:4433").await?;

    println!("✓ Connected with quantum-safe encryption!");
    if let Some(suite) = conn.cipher_suite() {
        println!("  Cipher Suite: {:?}", suite);
    }
    println!();

    // Send test messages
    let messages = [
        "Hello from the quantum world!",
        "Testing post-quantum cryptography",
        "QSSL protects against quantum computers",
        "quit",
    ];

    for msg in &messages {
        println!("Sending: {}", msg);
        conn.send(msg.as_bytes()).await?;

        if *msg != "quit" {
            let response = conn.recv().await?;
            println!("Server echo: {}\n", String::from_utf8_lossy(&response));
            sleep(Duration::from_secs(1)).await;
        }
    }

    conn.close().await?;
    println!("\n✓ Connection closed");

    Ok(())
}

/// Run performance benchmark
async fn run_benchmark() -> QsslResult<()> {
    println!("=== QSSL Performance Benchmark ===\n");

    // Benchmark cipher suites
    let suites = [
        qssl::crypto::CipherSuite::Kyber512Falcon512Aes128,
        qssl::crypto::CipherSuite::Kyber768Falcon512Aes256,
        qssl::crypto::CipherSuite::Kyber1024Falcon1024Aes256,
    ];

    for suite in &suites {
        println!("Testing {:?}:", suite);
        benchmark_suite(*suite).await?;
        println!();
    }

    Ok(())
}

/// Benchmark a specific cipher suite
async fn benchmark_suite(suite: qssl::crypto::CipherSuite) -> QsslResult<()> {
    use std::time::Instant;

    // Key generation
    let start = Instant::now();
    let kem_algo = suite.kem_algorithm();
    let (pk, sk) = qssl::crypto::kyber::generate_keypair(kem_algo)?;
    let keygen_time = start.elapsed();
    println!("  Key Generation: {:?}", keygen_time);

    // Encapsulation
    let start = Instant::now();
    let (ct, ss1) = qssl::crypto::kyber::encapsulate(&pk)?;
    let encap_time = start.elapsed();
    println!("  Encapsulation: {:?}", encap_time);

    // Decapsulation
    let start = Instant::now();
    let ss2 = qssl::crypto::kyber::decapsulate(&ct, &sk)?;
    let decap_time = start.elapsed();
    println!("  Decapsulation: {:?}", decap_time);

    // Verify
    assert_eq!(ss1.as_bytes(), ss2.as_bytes());

    // Signature test
    let sig_algo = suite.signature_algorithm();
    if let Ok((spk, ssk)) = qssl::crypto::falcon::generate_keypair(sig_algo) {
        let message = b"Benchmark message";

        let start = Instant::now();
        let signature = qssl::crypto::falcon::sign(message, &ssk)?;
        let sign_time = start.elapsed();
        println!("  Signing: {:?}", sign_time);

        let start = Instant::now();
        let valid = qssl::crypto::falcon::verify(message, &signature, &spk)?;
        let verify_time = start.elapsed();
        println!("  Verification: {:?} (valid: {})", verify_time, valid);
    }

    // Encryption benchmark
    let cipher = suite.symmetric_cipher();
    let key = qssl::crypto::symmetric::SymmetricKey::generate(cipher);
    let plaintext = vec![0u8; 1024]; // 1KB message

    let start = Instant::now();
    let (ciphertext, nonce) = qssl::crypto::symmetric::encrypt(&key, &plaintext, None)?;
    let encrypt_time = start.elapsed();
    println!("  Encryption (1KB): {:?}", encrypt_time);

    let start = Instant::now();
    let decrypted = qssl::crypto::symmetric::decrypt(&key, &ciphertext, &nonce, None)?;
    let decrypt_time = start.elapsed();
    println!("  Decryption (1KB): {:?}", decrypt_time);

    assert_eq!(plaintext, decrypted);

    // Calculate throughput
    let ops_per_sec = 1.0 / keygen_time.as_secs_f64();
    println!("  Throughput: {:.0} handshakes/sec", ops_per_sec);

    Ok(())
}

// Helper function to display connection info
fn display_connection_info(conn: &QsslConnection) {
    println!("\n=== Connection Info ===");
    println!("Role: {:?}", conn.role());
    if let Some(suite) = conn.cipher_suite() {
        println!("Cipher Suite: {:?}", suite);
        println!("  KEM: {:?}", suite.kem_algorithm());
        println!("  Signature: {:?}", suite.signature_algorithm());
        println!("  Cipher: {:?}", suite.symmetric_cipher());
        println!("  Hash: {:?}", suite.hash_algorithm());
    }
    println!("Session Resumed: {}", conn.is_resumed());
    if let Some(id) = conn.session_id() {
        println!("Session ID: {:?}", hex::encode(id));
    }
    println!("====================\n");
}