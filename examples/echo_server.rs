//! QSSL Echo Server Example
//!
//! Run with: cargo run --example echo_server

use qssl::{QsslConnection, QsslResult};
use tokio::net::TcpListener;
use tokio::time::{sleep, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

static CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() -> QsslResult<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    // Initialize QSSL
    qssl::init()?;

    let addr = "0.0.0.0:4433";
    log::info!("Starting QSSL Echo Server on {}", addr);
    log::info!("Protocol Version: 0x{:04X}", qssl::protocol_version());
    log::info!("QSSL Version: {}", qssl::version());

    let listener = TcpListener::bind(addr).await?;
    log::info!("Server listening for quantum-safe connections...");

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let conn_id = CONNECTION_COUNT.fetch_add(1, Ordering::SeqCst);
                log::info!("[{}] New connection from: {}", conn_id, peer_addr);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(conn_id, stream).await {
                        log::error!("[{}] Connection error: {}", conn_id, e);
                    }
                });
            }
            Err(e) => {
                log::error!("Failed to accept connection: {}", e);
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn handle_connection(conn_id: usize, stream: tokio::net::TcpStream) -> QsslResult<()> {
    log::info!("[{}] Starting QSSL handshake...", conn_id);
    let start = std::time::Instant::now();

    // Perform QSSL handshake
    let conn = match QsslConnection::accept(stream).await {
        Ok(c) => c,
        Err(e) => {
            log::error!("[{}] Handshake failed: {}", conn_id, e);
            return Err(e);
        }
    };

    let handshake_time = start.elapsed();
    log::info!("[{}] ✅ Handshake complete in {:?}", conn_id, handshake_time);

    // Display connection info
    if let Some(suite) = conn.cipher_suite() {
        log::info!("[{}] Cipher Suite: {:?}", conn_id, suite);
        log::info!("[{}]   - KEM: {:?}", conn_id, suite.kem_algorithm());
        log::info!("[{}]   - Signature: {:?}", conn_id, suite.signature_algorithm());
        log::info!("[{}]   - Cipher: {:?}", conn_id, suite.symmetric_cipher());
        log::info!("[{}]   - Hash: {:?}", conn_id, suite.hash_algorithm());
    }

    log::info!("[{}] Entering echo loop...", conn_id);
    let mut msg_count = 0;

    // Echo server loop
    loop {
        match conn.recv().await {
            Ok(data) => {
                msg_count += 1;
                let msg = String::from_utf8_lossy(&data);

                log::info!("[{}] Message {}: {} bytes - \"{}\"",
                    conn_id, msg_count, data.len(),
                    if msg.len() > 50 {
                        format!("{}...", &msg[..50])
                    } else {
                        msg.to_string()
                    }
                );

                // Check for quit command
                if msg.trim() == "quit" {
                    log::info!("[{}] Client requested disconnect", conn_id);
                    break;
                }

                // Echo back
                if let Err(e) = conn.send(&data).await {
                    log::error!("[{}] Failed to echo: {}", conn_id, e);
                    break;
                }
            }
            Err(e) => {
                log::info!("[{}] Connection closed: {}", conn_id, e);
                break;
            }
        }
    }

    // Close connection
    if let Err(e) = conn.close().await {
        log::warn!("[{}] Error closing connection: {}", conn_id, e);
    }

    log::info!("[{}] Connection closed after {} messages", conn_id, msg_count);
    Ok(())
}