//! QSSL Echo Client Example
//!
//! Run with: cargo run --example echo_client

use qssl::{QsslConnection, QsslResult};
use tokio::time::{sleep, Duration};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> QsslResult<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // Initialize QSSL
    qssl::init()?;

    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost:4433".to_string());

    log::info!("QSSL Echo Client");
    log::info!("Connecting to {}...", server);

    let start = std::time::Instant::now();

    // Connect with QSSL
    let conn = match QsslConnection::connect(&server).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to connect: {}", e);
            return Err(e);
        }
    };

    let connect_time = start.elapsed();
    log::info!("✅ Connected in {:?}", connect_time);

    // Display connection info
    if let Some(suite) = conn.cipher_suite() {
        log::info!("Negotiated Cipher Suite: {:?}", suite);
        log::info!("  - KEM: {:?}", suite.kem_algorithm());
        log::info!("  - Signature: {:?}", suite.signature_algorithm());
        log::info!("  - Cipher: {:?}", suite.symmetric_cipher());
        log::info!("  - Hash: {:?}", suite.hash_algorithm());
    }

    println!("\nQuantum-Safe connection established!");
    println!("Type messages to send to the server (or 'quit' to exit):\n");

    // Interactive mode or automatic test mode
    if std::env::var("QSSL_TEST_MODE").is_ok() {
        // Automatic test mode
        run_test_sequence(&conn).await?;
    } else {
        // Interactive mode
        run_interactive(&conn).await?;
    }

    // Close connection
    log::info!("Closing connection...");
    conn.close().await?;
    log::info!("✅ Connection closed cleanly");

    Ok(())
}

async fn run_interactive(conn: &QsslConnection) -> QsslResult<()> {
    // Note: In a real implementation, we'd need proper connection sharing
    // For this example, we'll use synchronous request-response

    // Read from stdin and send
    let stdin = io::stdin();
    let mut buffer = String::new();

    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        buffer.clear();
        stdin.read_line(&mut buffer).unwrap();

        let message = buffer.trim();
        if message.is_empty() {
            continue;
        }

        // Send message
        conn.send(message.as_bytes()).await?;

        if message == "quit" {
            break;
        }

        // Receive echo response
        match conn.recv().await {
            Ok(data) => {
                let response = String::from_utf8_lossy(&data);
                println!("📨 Server echo: {}", response);
            }
            Err(e) => {
                println!("Error receiving response: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn run_test_sequence(conn: &QsslConnection) -> QsslResult<()> {
    log::info!("Running test sequence...");

    let large_msg = format!("Large message: {}", "x".repeat(1000));
    let test_messages = vec![
        ("Hello, Quantum World!".to_string(), 100),
        ("Testing QSSL protocol with post-quantum cryptography".to_string(), 100),
        ("🔐 Unicode test: 你好世界".to_string(), 100),
        ("Small".to_string(), 50),
        (large_msg, 200),
        ("Final test message".to_string(), 100),
        ("quit".to_string(), 100),
    ];

    for (msg, delay_ms) in test_messages.iter() {
        log::info!("Sending: {}", if msg.len() > 50 {
            format!("{}...", &msg[..50])
        } else {
            msg.to_string()
        });

        // Send
        let start = std::time::Instant::now();
        conn.send(msg.as_bytes()).await?;

        if *msg != "quit" {
            // Receive echo
            let response = conn.recv().await?;
            let rtt = start.elapsed();

            let response_str = String::from_utf8_lossy(&response);
            log::info!("Received echo: {} (RTT: {:?})",
                if response_str.len() > 50 {
                    format!("{}...", &response_str[..50])
                } else {
                    response_str.to_string()
                },
                rtt
            );

            assert_eq!(msg.as_bytes(), &response[..], "Echo mismatch!");
        }

        sleep(Duration::from_millis(*delay_ms as u64)).await;
    }

    log::info!("✅ All test messages successful!");
    Ok(())
}

// Note: QsslConnection is not cloneable in this example
// In production, we'd implement proper connection sharing using Arc