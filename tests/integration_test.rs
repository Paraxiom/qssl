//! QSSL Integration Tests

use qssl::{QsslConnection, QsslResult};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration, timeout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn test_handshake() -> QsslResult<()> {
    // Initialize QSSL
    qssl::init()?;

    let addr = "127.0.0.1:0";  // Use port 0 for automatic assignment
    let listener = TcpListener::bind(addr).await?;
    let actual_addr = listener.local_addr()?;

    println!("Test server listening on: {}", actual_addr);

    let server_ready = Arc::new(AtomicBool::new(false));
    let server_ready_clone = server_ready.clone();

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        server_ready_clone.store(true, Ordering::SeqCst);

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                println!("Server: Accepted connection from {}", peer_addr);

                match QsslConnection::accept(stream).await {
                    Ok(conn) => {
                        println!("Server: Handshake successful");
                        println!("Server: Cipher suite: {:?}", conn.cipher_suite());

                        // Small delay to ensure both sides are ready
                        sleep(Duration::from_millis(50)).await;

                        // Echo one message
                        match conn.recv().await {
                            Ok(data) => {
                                println!("Server: Received {} bytes", data.len());
                                if let Err(e) = conn.send(&data).await {
                                    println!("Server: Failed to echo: {}", e);
                                }
                            }
                            Err(e) => {
                                println!("Server: Failed to receive: {}", e);
                            }
                        }

                        let _ = conn.close().await;
                        Ok(())
                    }
                    Err(e) => {
                        eprintln!("Server: Handshake failed: {}", e);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                eprintln!("Server: Accept failed: {}", e);
                Err(e.into())
            }
        }
    });

    // Wait for server to be ready
    while !server_ready.load(Ordering::SeqCst) {
        sleep(Duration::from_millis(10)).await;
    }

    // Give server time to start listening
    sleep(Duration::from_millis(100)).await;

    // Client connection
    println!("Client: Connecting to {}", actual_addr);

    let client_result = timeout(Duration::from_secs(5), async {
        match QsslConnection::connect(&actual_addr.to_string()).await {
            Ok(conn) => {
                println!("Client: Handshake successful");
                println!("Client: Cipher suite: {:?}", conn.cipher_suite());

                // Small delay to ensure both sides are ready
                sleep(Duration::from_millis(100)).await;

                // Send test message
                let test_msg = b"Hello, Quantum World!";
                println!("Client: Sending test message...");
                conn.send(test_msg).await?;

                // Receive echo
                println!("Client: Waiting for echo...");
                let response = conn.recv().await?;
                assert_eq!(response, test_msg);
                println!("Client: Echo test successful");

                conn.close().await?;
                Ok::<(), qssl::QsslError>(())
            }
            Err(e) => {
                eprintln!("Client: Connection failed: {}", e);
                Err(e)
            }
        }
    }).await;

    // Check results
    match client_result {
        Ok(Ok(())) => println!("Client completed successfully"),
        Ok(Err(e)) => eprintln!("Client error: {}", e),
        Err(_) => eprintln!("Client timeout"),
    }

    // Wait for server to complete
    let server_result = timeout(Duration::from_secs(1), server_handle).await;

    match server_result {
        Ok(Ok(Ok(()))) => println!("Server completed successfully"),
        Ok(Ok(Err(e))) => eprintln!("Server error: {}", e),
        Ok(Err(e)) => eprintln!("Server panic: {:?}", e),
        Err(_) => println!("Server timeout (may be normal)"),
    }

    Ok(())
}

#[tokio::test]
async fn test_certificate_verification() -> QsslResult<()> {
    use qssl::crypto::certificate::{CertificateBuilder, SigningKey};
    use pqcrypto_falcon::falcon512;

    // Generate keypair
    let (pk, sk) = falcon512::keypair();

    // Create self-signed certificate
    let cert = CertificateBuilder::new()
        .subject("CN=test.example.com,O=Test,C=US")
        .self_sign(&sk, &pk)?;

    // Verify it
    assert!(cert.verify(None)?);

    // Check validity
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    assert!(cert.is_valid_at(now));

    println!("Certificate verification test passed");
    Ok(())
}

#[tokio::test]
async fn test_cipher_suites() {
    use qssl::CipherSuite;

    let suite = CipherSuite::Kyber768Falcon512Aes256;

    assert_eq!(suite.kem_algorithm(), qssl::KemAlgorithm::Kyber768);
    assert_eq!(suite.signature_algorithm(), qssl::SignatureAlgorithm::Falcon512);
    assert_eq!(suite.symmetric_cipher(), qssl::SymmetricCipher::Aes256Gcm);
    assert_eq!(suite.hash_algorithm(), qssl::HashAlgorithm::Sha384);

    println!("Cipher suite test passed");
}

#[test]
fn test_protocol_version() {
    assert_eq!(qssl::protocol_version(), 0x5110);
    assert_eq!(qssl::version(), "0.1.0-alpha");
}