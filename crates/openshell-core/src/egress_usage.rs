// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Egress usage monitoring limits and defaults shared by the supervisor and
//! the gateway.

use std::time::Duration;

/// Maximum number of `network_budgets` entries in one policy.
pub const MAX_NETWORK_BUDGETS: usize = 32;

/// Maximum number of host patterns in one budget selector.
pub const MAX_BUDGET_HOST_PATTERNS: usize = 32;

/// Default usage window.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Default novelty learning period.
pub const DEFAULT_LEARNING_PERIOD: Duration = Duration::from_secs(600);

/// Default drift ratio above the baseline.
pub const DEFAULT_DRIFT_RATIO: u32 = 10;

/// Default minimum requests in a window before a request counter can drift.
pub const DEFAULT_DRIFT_MIN_REQUESTS: u64 = 100;

/// Default minimum bytes in a window before a byte counter can drift.
pub const DEFAULT_DRIFT_MIN_BYTES: u64 = 100 * 1024 * 1024;

/// Usage table entries per sandbox, excluding overflow entries.
pub const MAX_USAGE_ENTRIES: usize = 1024;

/// Rule-hit entries per usage summary.
pub const MAX_RULE_HITS_PER_SUMMARY: usize = 64;

/// Novelty items per kind per policy key.
pub const MAX_NOVELTY_ITEMS_PER_KIND: usize = 256;

/// Novelty items per sandbox.
pub const MAX_NOVELTY_ITEMS: usize = 4096;

/// Findings carried by one usage report.
pub const MAX_FINDINGS_PER_REPORT: usize = 64;

/// Usage reports kept in the supervisor outbox.
pub const MAX_OUTBOX_REPORTS: usize = 10;

/// Windows without traffic before an unpinned usage entry is removed.
pub const IDLE_WINDOWS_BEFORE_REMOVAL: u64 = 10;

/// Rule ID recorded for a request that audit mode forwards without a matching rule.
pub const AUDIT_FORWARDED_RULE_ID: &str = "audit_forwarded";
