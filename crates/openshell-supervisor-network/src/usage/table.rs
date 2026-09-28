// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded usage table: one entry of atomic counters per usage key.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use openshell_core::egress_usage::{
    IDLE_WINDOWS_BEFORE_REMOVAL, MAX_RULE_HITS_PER_SUMMARY, MAX_USAGE_ENTRIES,
};

/// Grouping key of usage counters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UsageKey {
    pub policy_key: String,
    pub endpoint_id: String,
    pub host: String,
    pub port: u16,
    pub binary_path: String,
    pub binary_sha256: String,
}

/// Response status classes observed from the upstream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponseCounts {
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub status_429: u64,
}

/// Counters for one usage key and one policy revision.
#[derive(Debug)]
pub struct UsageEntry {
    pub key: UsageKey,
    pub policy_hash: Arc<str>,
    pub overflow: bool,
    connections: AtomicU64,
    requests: AtomicU64,
    write_requests: AtomicU64,
    bytes_out: AtomicU64,
    bytes_in: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    status_429: AtomicU64,
    budget_denials: AtomicU64,
    rule_hits: Mutex<BTreeMap<String, u64>>,
    idle_windows: AtomicU64,
}

impl UsageEntry {
    fn new(key: UsageKey, policy_hash: Arc<str>, overflow: bool) -> Self {
        Self {
            key,
            policy_hash,
            overflow,
            connections: AtomicU64::new(0),
            requests: AtomicU64::new(0),
            write_requests: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            status_429: AtomicU64::new(0),
            budget_denials: AtomicU64::new(0),
            rule_hits: Mutex::new(BTreeMap::new()),
            idle_windows: AtomicU64::new(0),
        }
    }

    pub fn add_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_request(&self, rule_ids: &[String], write: bool) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if write {
            self.write_requests.fetch_add(1, Ordering::Relaxed);
        }
        if rule_ids.is_empty() {
            return;
        }
        let mut hits = self
            .rule_hits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for rule_id in rule_ids {
            if hits.len() < MAX_RULE_HITS_PER_SUMMARY || hits.contains_key(rule_id) {
                *hits.entry(rule_id.clone()).or_default() += 1;
            } else {
                *hits.entry(RULE_HIT_OVERFLOW.to_string()).or_default() += 1;
            }
        }
    }

    pub fn add_bytes_out(&self, amount: u64) {
        self.bytes_out.fetch_add(amount, Ordering::Relaxed);
    }

    pub fn add_bytes_in(&self, amount: u64) {
        self.bytes_in.fetch_add(amount, Ordering::Relaxed);
    }

    pub fn add_budget_denial(&self) {
        self.budget_denials.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_status(&self, status: u16) {
        let counter = match status {
            429 => &self.status_429,
            200..=299 => &self.status_2xx,
            300..=399 => &self.status_3xx,
            400..=499 => &self.status_4xx,
            500..=599 => &self.status_5xx,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn drain(&self) -> Option<UsageSummary> {
        let take = |counter: &AtomicU64| counter.swap(0, Ordering::AcqRel);
        let connections = take(&self.connections);
        let requests = take(&self.requests);
        let write_requests = take(&self.write_requests);
        let bytes_out = take(&self.bytes_out);
        let bytes_in = take(&self.bytes_in);
        let responses = ResponseCounts {
            status_2xx: take(&self.status_2xx),
            status_3xx: take(&self.status_3xx),
            status_4xx: take(&self.status_4xx),
            status_5xx: take(&self.status_5xx),
            status_429: take(&self.status_429),
        };
        let budget_denials = take(&self.budget_denials);
        let rule_hits = std::mem::take(
            &mut *self
                .rule_hits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let active = connections > 0
            || requests > 0
            || bytes_out > 0
            || bytes_in > 0
            || budget_denials > 0
            || responses != ResponseCounts::default();
        if !active {
            self.idle_windows.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.idle_windows.store(0, Ordering::Relaxed);
        Some(UsageSummary {
            key: self.key.clone(),
            policy_hash: self.policy_hash.to_string(),
            overflow: self.overflow,
            connections,
            requests,
            write_requests,
            bytes_out,
            bytes_in,
            responses,
            rule_hits: rule_hits.into_iter().collect(),
            budget_denials,
        })
    }
}

/// Rule-hit key that collects rule IDs above the per-summary bound.
pub const RULE_HIT_OVERFLOW: &str = "other";

/// Counters of one usage key over one window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSummary {
    pub key: UsageKey,
    pub policy_hash: String,
    pub overflow: bool,
    pub connections: u64,
    pub requests: u64,
    pub write_requests: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub responses: ResponseCounts,
    pub rule_hits: Vec<(String, u64)>,
    pub budget_denials: u64,
}

/// Result of a table lookup.
pub struct TableLookup {
    pub entry: Arc<UsageEntry>,
    pub inserted: bool,
    pub overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OverflowKey {
    policy_key: String,
    endpoint_id: String,
    policy_hash: Arc<str>,
}

/// Bounded usage table keyed by usage key and policy hash. A policy hash
/// change seals old entries by construction: new admissions use new keys.
#[derive(Debug, Default)]
pub struct UsageTable {
    entries: HashMap<(UsageKey, Arc<str>), Arc<UsageEntry>>,
    overflow: HashMap<OverflowKey, Arc<UsageEntry>>,
}

impl UsageTable {
    pub fn get_or_insert(&mut self, key: &UsageKey, policy_hash: &Arc<str>) -> TableLookup {
        if let Some(entry) = self.entries.get(&(key.clone(), policy_hash.clone())) {
            return TableLookup {
                entry: entry.clone(),
                inserted: false,
                overflowed: false,
            };
        }
        if self.entries.len() < MAX_USAGE_ENTRIES {
            let entry = Arc::new(UsageEntry::new(key.clone(), policy_hash.clone(), false));
            self.entries
                .insert((key.clone(), policy_hash.clone()), entry.clone());
            return TableLookup {
                entry,
                inserted: true,
                overflowed: false,
            };
        }
        let overflow_key = OverflowKey {
            policy_key: key.policy_key.clone(),
            endpoint_id: key.endpoint_id.clone(),
            policy_hash: policy_hash.clone(),
        };
        let mut inserted = false;
        let entry = self
            .overflow
            .entry(overflow_key)
            .or_insert_with(|| {
                inserted = true;
                Arc::new(UsageEntry::new(
                    UsageKey {
                        policy_key: key.policy_key.clone(),
                        endpoint_id: key.endpoint_id.clone(),
                        host: "*".to_string(),
                        port: key.port,
                        binary_path: String::new(),
                        binary_sha256: String::new(),
                    },
                    policy_hash.clone(),
                    true,
                ))
            })
            .clone();
        TableLookup {
            entry,
            inserted,
            overflowed: true,
        }
    }

    /// Read and reset every entry. Remove entries that no attribution
    /// references and that are idle or belong to an older policy revision.
    pub fn drain(&mut self, current_policy_hash: &str) -> Vec<UsageSummary> {
        let mut summaries = Vec::new();
        let mut drain_map = |map: &mut dyn Iterator<Item = &Arc<UsageEntry>>| {
            for entry in map {
                if let Some(summary) = entry.drain() {
                    summaries.push(summary);
                }
            }
        };
        drain_map(&mut self.entries.values());
        drain_map(&mut self.overflow.values());
        let removable = |entry: &Arc<UsageEntry>| {
            Arc::strong_count(entry) == 1
                && (&*entry.policy_hash != current_policy_hash
                    || entry.idle_windows.load(Ordering::Relaxed) >= IDLE_WINDOWS_BEFORE_REMOVAL)
        };
        self.entries.retain(|_, entry| !removable(entry));
        self.overflow.retain(|_, entry| !removable(entry));
        summaries.sort_by(|left, right| left.key.cmp(&right.key));
        summaries
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len() + self.overflow.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str) -> UsageKey {
        UsageKey {
            policy_key: "api".into(),
            endpoint_id: "endpoint:v1:a".into(),
            host: host.into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: "abc".into(),
        }
    }

    #[test]
    fn drain_reads_and_resets_counters() {
        let mut table = UsageTable::default();
        let hash: Arc<str> = Arc::from("h1");
        let entry = table.get_or_insert(&key("a.example.com"), &hash).entry;
        entry.add_connection();
        entry.add_request(&["rule:1".into()], false);
        entry.add_bytes_out(10);
        entry.add_bytes_in(20);
        entry.record_status(200);
        entry.record_status(429);
        let summaries = table.drain("h1");
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!((summary.connections, summary.requests), (1, 1));
        assert_eq!((summary.bytes_out, summary.bytes_in), (10, 20));
        assert_eq!(summary.responses.status_2xx, 1);
        assert_eq!(summary.responses.status_429, 1);
        assert_eq!(summary.rule_hits, [("rule:1".to_string(), 1)]);
        assert!(table.drain("h1").is_empty());
    }

    #[test]
    fn full_table_diverts_new_keys_to_one_overflow_entry_per_endpoint() {
        let mut table = UsageTable::default();
        let hash: Arc<str> = Arc::from("h1");
        let pinned: Vec<_> = (0..MAX_USAGE_ENTRIES)
            .map(|index| table.get_or_insert(&key(&format!("h{index}")), &hash).entry)
            .collect();
        let first = table.get_or_insert(&key("new-1"), &hash);
        let second = table.get_or_insert(&key("new-2"), &hash);
        assert!(first.overflowed && first.inserted);
        assert!(second.overflowed && !second.inserted);
        assert!(Arc::ptr_eq(&first.entry, &second.entry));
        assert_eq!(first.entry.key.endpoint_id, "endpoint:v1:a");
        assert_eq!(table.len(), MAX_USAGE_ENTRIES + 1);
        drop(pinned);
    }

    #[test]
    fn pinned_entry_survives_idle_and_policy_change() {
        let mut table = UsageTable::default();
        let old: Arc<str> = Arc::from("old");
        let pinned = table.get_or_insert(&key("a"), &old).entry;
        let unpinned = table.get_or_insert(&key("b"), &old).entry;
        drop(unpinned);
        for _ in 0..=IDLE_WINDOWS_BEFORE_REMOVAL {
            table.drain("new");
        }
        assert_eq!(table.len(), 1, "only the pinned entry remains");

        // A late write to the sealed entry is still reported, then the entry
        // is removed once the attribution releases it.
        pinned.add_bytes_in(5);
        drop(pinned);
        let summaries = table.drain("new");
        assert_eq!(summaries[0].bytes_in, 5);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn new_policy_hash_creates_a_new_entry() {
        let mut table = UsageTable::default();
        let old: Arc<str> = Arc::from("old");
        let new: Arc<str> = Arc::from("new");
        let first = table.get_or_insert(&key("a"), &old).entry;
        let second = table.get_or_insert(&key("a"), &new).entry;
        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn rule_hits_are_bounded() {
        let mut table = UsageTable::default();
        let hash: Arc<str> = Arc::from("h");
        let entry = table.get_or_insert(&key("a"), &hash).entry;
        for index in 0..(MAX_RULE_HITS_PER_SUMMARY + 5) {
            entry.add_request(&[format!("rule:{index}")], false);
        }
        let summary = table.drain("h").remove(0);
        assert_eq!(summary.rule_hits.len(), MAX_RULE_HITS_PER_SUMMARY + 1);
        assert!(
            summary
                .rule_hits
                .iter()
                .any(|(rule, count)| rule == RULE_HIT_OVERFLOW && *count == 5)
        );
    }
}
