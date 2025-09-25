//! Quantum Frame Format - All frames are indistinguishable

use super::{QuantumFrame, FrameType, QUANTUM_FRAME_SIZE};
use crate::{QsslError, QsslResult};
use rand::RngCore;

/// Frame builder for creating indistinguishable frames
pub struct FrameBuilder {
    sequence: u64,
    frame_type: FrameType,
    payload: Vec<u8>,
    padding_strategy: PaddingStrategy,
}

/// Padding strategies to hide message sizes
#[derive(Debug, Clone, Copy)]
pub enum PaddingStrategy {
    /// Minimum padding (fastest)
    Minimal,
    /// Random padding (balanced)
    Random,
    /// Maximum padding (most secure)
    Maximum,
    /// Adaptive based on traffic analysis
    Adaptive,
}

impl FrameBuilder {
    /// Create new frame builder
    pub fn new(sequence: u64, frame_type: FrameType) -> Self {
        Self {
            sequence,
            frame_type,
            payload: Vec::new(),
            padding_strategy: PaddingStrategy::Random,
        }
    }

    /// Set padding strategy
    pub fn with_padding(mut self, strategy: PaddingStrategy) -> Self {
        self.padding_strategy = strategy;
        self
    }

    /// Set payload data
    pub fn with_payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    /// Build the frame with appropriate padding
    pub fn build(self) -> QsslResult<QuantumFrame> {
        let mut frame = QuantumFrame {
            header: super::EncryptedHeader {
                sequence: self.sequence.to_be_bytes(),
                timestamp: Self::current_timestamp(),
                frame_type: self.frame_type as u8,
            },
            payload: [0; 719],
            mac: [0; 32],
        };

        // Add payload with length prefix
        let payload_len = self.payload.len().min(717);
        frame.payload[0..2].copy_from_slice(&(payload_len as u16).to_be_bytes());
        frame.payload[2..2 + payload_len].copy_from_slice(&self.payload[..payload_len]);

        // Apply padding strategy
        self.apply_padding(&mut frame.payload[2 + payload_len..]);

        Ok(frame)
    }

    /// Apply padding based on strategy
    fn apply_padding(&self, buffer: &mut [u8]) {
        match self.padding_strategy {
            PaddingStrategy::Minimal => {
                // Just fill with zeros (fastest but less secure)
                buffer.fill(0);
            }
            PaddingStrategy::Random => {
                // Random padding (good balance)
                rand::thread_rng().fill_bytes(buffer);
            }
            PaddingStrategy::Maximum => {
                // Maximum entropy padding
                for chunk in buffer.chunks_mut(32) {
                    let mut rng = rand::thread_rng();
                    rng.fill_bytes(chunk);
                    // Additional mixing
                    for i in 1..chunk.len() {
                        chunk[i] ^= chunk[i - 1].rotate_left(3);
                    }
                }
            }
            PaddingStrategy::Adaptive => {
                // Adaptive padding based on traffic patterns
                // This would analyze recent traffic and adapt
                self.adaptive_padding(buffer);
            }
        }
    }

    /// Adaptive padding to confuse traffic analysis
    fn adaptive_padding(&self, buffer: &mut [u8]) {
        // Create padding that looks like legitimate data patterns
        let patterns = [
            0xFF, 0x00, 0xAA, 0x55, // Common bit patterns
            0x01, 0x02, 0x04, 0x08, // Powers of 2
            0x10, 0x20, 0x40, 0x80,
        ];

        let mut rng = rand::thread_rng();
        let pattern_choice = rng.next_u32() as usize % patterns.len();
        let base_pattern = patterns[pattern_choice];

        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = match i % 4 {
                0 => base_pattern,
                1 => base_pattern.rotate_right(1),
                2 => !base_pattern,
                3 => rng.next_u32() as u8,
                _ => 0,
            };
        }
    }

    /// Get current timestamp in microseconds
    fn current_timestamp() -> [u8; 8] {
        use std::time::{SystemTime, UNIX_EPOCH};

        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        micros.to_be_bytes()
    }
}

/// Frame parser for reading indistinguishable frames
pub struct FrameParser {
    /// Buffer for partial frames
    buffer: Vec<u8>,
}

impl FrameParser {
    /// Create new parser
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(QUANTUM_FRAME_SIZE * 2),
        }
    }

    /// Add data to buffer
    pub fn add_data(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to parse a complete frame
    pub fn parse_frame(&mut self) -> Option<QuantumFrame> {
        if self.buffer.len() < QUANTUM_FRAME_SIZE {
            return None;
        }

        // Extract frame bytes
        let frame_bytes: [u8; QUANTUM_FRAME_SIZE] =
            self.buffer[..QUANTUM_FRAME_SIZE].try_into().ok()?;

        // Remove from buffer
        self.buffer.drain(..QUANTUM_FRAME_SIZE);

        // Reconstruct frame (unsafe but controlled)
        let frame = unsafe {
            std::mem::transmute::<[u8; QUANTUM_FRAME_SIZE], QuantumFrame>(frame_bytes)
        };

        Some(frame)
    }

    /// Check if we have enough data for a frame
    pub fn has_complete_frame(&self) -> bool {
        self.buffer.len() >= QUANTUM_FRAME_SIZE
    }

    /// Clear buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

/// Traffic pattern obfuscator
pub struct TrafficObfuscator {
    /// Timing variance in microseconds
    timing_variance: u32,

    /// Minimum inter-frame delay
    min_delay: std::time::Duration,

    /// Maximum inter-frame delay
    max_delay: std::time::Duration,
}

impl TrafficObfuscator {
    /// Create new obfuscator
    pub fn new() -> Self {
        Self {
            timing_variance: 1000, // 1ms variance
            min_delay: std::time::Duration::from_micros(100),
            max_delay: std::time::Duration::from_millis(10),
        }
    }

    /// Get randomized delay for next frame
    pub fn next_delay(&self) -> std::time::Duration {
        let mut rng = rand::thread_rng();
        let variance = (rng.next_u32() % self.timing_variance) as u64;

        let base_delay = self.min_delay.as_micros() as u64;
        let total_delay = base_delay + variance;

        let delay = std::time::Duration::from_micros(total_delay);

        // Cap at max delay
        if delay > self.max_delay {
            self.max_delay
        } else {
            delay
        }
    }

    /// Apply timing obfuscation
    pub async fn obfuscate_timing(&self) {
        let delay = self.next_delay();
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_builder() {
        let frame = FrameBuilder::new(1, FrameType::Data)
            .with_payload(b"test data")
            .with_padding(PaddingStrategy::Random)
            .build()
            .unwrap();

        // Frame should be exactly the right size
        let size = std::mem::size_of_val(&frame);
        assert_eq!(size, QUANTUM_FRAME_SIZE);
    }

    #[test]
    fn test_frame_parser() {
        let mut parser = FrameParser::new();

        // Add partial data
        parser.add_data(&[0u8; 100]);
        assert!(!parser.has_complete_frame());

        // Add enough for complete frame
        parser.add_data(&[0u8; QUANTUM_FRAME_SIZE - 100]);
        assert!(parser.has_complete_frame());

        // Parse frame
        let frame = parser.parse_frame();
        assert!(frame.is_some());
        assert!(!parser.has_complete_frame());
    }

    #[test]
    fn test_padding_strategies() {
        let data = b"small";

        for strategy in [
            PaddingStrategy::Minimal,
            PaddingStrategy::Random,
            PaddingStrategy::Maximum,
            PaddingStrategy::Adaptive,
        ] {
            let frame = FrameBuilder::new(0, FrameType::Data)
                .with_payload(data)
                .with_padding(strategy)
                .build()
                .unwrap();

            // All frames should be same size regardless of padding
            assert_eq!(std::mem::size_of_val(&frame), QUANTUM_FRAME_SIZE);
        }
    }

    #[tokio::test]
    async fn test_traffic_obfuscator() {
        let obfuscator = TrafficObfuscator::new();

        let start = std::time::Instant::now();
        obfuscator.obfuscate_timing().await;
        let elapsed = start.elapsed();

        // Should have some delay
        assert!(elapsed >= obfuscator.min_delay);
        assert!(elapsed <= obfuscator.max_delay);
    }
}