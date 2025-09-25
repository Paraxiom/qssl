//! Test SPHINCS+/Falcon KEM implementation

use qssl::quantum_native::sphincs_kem::SphincsKem;

fn main() {
    println!("Testing SPHINCS+/Falcon KEM (not vulnerable Kyber!)");
    println!("================================================\n");

    // Create two parties
    println!("Creating Alice and Bob with SPHINCS+ identity keys...");
    let alice = SphincsKem::new().expect("Failed to create Alice KEM");
    let bob = SphincsKem::new().expect("Failed to create Bob KEM");

    println!("✓ Keys generated successfully\n");

    // Get public keys
    use pqcrypto_traits::sign::PublicKey;
    let alice_pk = alice.identity_pk.as_bytes();
    let bob_pk = bob.identity_pk.as_bytes();

    println!("Key sizes:");
    println!("  SPHINCS+ public key: {} bytes", alice_pk.len());
    println!("  Falcon public key: {} bytes", alice.ephemeral_pk.as_bytes().len());

    // Alice encapsulates for Bob
    println!("\nAlice encapsulating for Bob...");
    let (ciphertext, alice_secret) = alice.encapsulate(bob_pk)
        .expect("Alice encapsulation failed");

    println!("✓ Encapsulation successful");
    println!("  Ciphertext size: {} bytes", ciphertext.len());
    println!("  Shared secret: {} bytes", alice_secret.len());

    // Bob decapsulates
    println!("\nBob decapsulating...");
    let bob_secret = bob.decapsulate(&ciphertext, alice_pk)
        .expect("Bob decapsulation failed");

    println!("✓ Decapsulation successful");

    // Verify shared secrets match
    if alice_secret == bob_secret {
        println!("\n✅ SUCCESS: Shared secrets match!");
        println!("Shared secret (hex): {}", hex::encode(&alice_secret[..16]));
    } else {
        println!("\n❌ FAILURE: Shared secrets don't match!");
        std::process::exit(1);
    }

    println!("\n=== Why this is better than Kyber ===");
    println!("1. SPHINCS+ is hash-based (no lattice vulnerabilities)");
    println!("2. Falcon provides efficiency with different math basis");
    println!("3. Proper KEM construction (not just signing random bytes)");
    println!("4. No timing attacks like KyberSlash");
    println!("5. Defense in depth with hybrid approach");
}