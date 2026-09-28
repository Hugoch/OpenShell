// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `network_traffic` object.

use serde::{Deserialize, Serialize};

/// OCSF Network Traffic object.
///
/// Directions follow OCSF: `bytes_out` is source to destination, `bytes_in`
/// is destination to source. For sandbox egress, the source is the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTraffic {
    /// Bytes sent from the destination to the source.
    pub bytes_in: u64,
    /// Bytes sent from the source to the destination.
    pub bytes_out: u64,
    /// Total bytes in both directions.
    pub bytes: u64,
}

impl NetworkTraffic {
    /// Create a traffic object from the two directional byte counts.
    #[must_use]
    pub fn new(bytes_out: u64, bytes_in: u64) -> Self {
        Self {
            bytes_in,
            bytes_out,
            bytes: bytes_in.saturating_add(bytes_out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_traffic_serializes_directional_and_total_bytes() {
        let traffic = NetworkTraffic::new(100, 2500);
        let json = serde_json::to_value(&traffic).unwrap();
        assert_eq!(json["bytes_out"], 100);
        assert_eq!(json["bytes_in"], 2500);
        assert_eq!(json["bytes"], 2600);
    }
}
