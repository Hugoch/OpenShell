// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Budget ledger: one token bucket per budget counter.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use openshell_core::host_pattern::HostPattern;
use tokio::time::Instant;

/// Budget counter kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counter {
    Requests,
    Connections,
    BytesOut,
    BytesIn,
}

impl Counter {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Requests => "requests_per_minute",
            Self::Connections => "connections_per_minute",
            Self::BytesOut => "bytes_out_per_hour",
            Self::BytesIn => "bytes_in_per_hour",
        }
    }

    const fn period(self) -> Duration {
        match self {
            Self::Requests | Self::Connections => Duration::from_mins(1),
            Self::BytesOut | Self::BytesIn => Duration::from_hours(1),
        }
    }
}

#[derive(Debug)]
struct BucketState {
    balance: f64,
    last_refill: Instant,
}

/// Token bucket whose capacity is the amount for one period. It refills at a
/// constant rate. Byte charges accumulate in an atomic and are folded into
/// the balance at the next admission, so the copy path takes no lock.
#[derive(Debug)]
pub struct TokenBucket {
    counter: Counter,
    capacity: AtomicU64,
    state: Mutex<BucketState>,
    pending_debit: AtomicU64,
}

impl TokenBucket {
    fn new(counter: Counter, capacity: u64, now: Instant) -> Self {
        Self {
            counter,
            capacity: AtomicU64::new(capacity),
            #[allow(clippy::cast_precision_loss)]
            state: Mutex::new(BucketState {
                balance: capacity as f64,
                last_refill: now,
            }),
            pending_debit: AtomicU64::new(0),
        }
    }

    pub const fn counter(&self) -> Counter {
        self.counter
    }

    #[allow(clippy::cast_precision_loss)]
    fn capacity(&self) -> f64 {
        self.capacity.load(Ordering::Relaxed) as f64
    }

    fn settle(&self, state: &mut BucketState, now: Instant) {
        let capacity = self.capacity();
        let elapsed = now.saturating_duration_since(state.last_refill);
        let refill = capacity * elapsed.as_secs_f64() / self.counter.period().as_secs_f64();
        state.balance = (state.balance + refill).min(capacity);
        state.last_refill = now;
        #[allow(clippy::cast_precision_loss)]
        let debit = self.pending_debit.swap(0, Ordering::AcqRel) as f64;
        state.balance -= debit;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BucketState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take one whole token if the balance allows it.
    pub fn try_take_one(&self, now: Instant) -> bool {
        let mut state = self.lock();
        self.settle(&mut state, now);
        if state.balance >= 1.0 {
            state.balance -= 1.0;
            true
        } else {
            false
        }
    }

    /// Take one token even without balance. Returns whether a whole token was available.
    pub fn force_take_one(&self, now: Instant) -> bool {
        let mut state = self.lock();
        self.settle(&mut state, now);
        let had_token = state.balance >= 1.0;
        state.balance -= 1.0;
        had_token
    }

    /// Return a token taken by an admission that a later budget denied.
    pub fn return_one(&self) {
        let mut state = self.lock();
        state.balance = (state.balance + 1.0).min(self.capacity());
    }

    /// Whether the balance is more than zero after pending byte charges.
    pub fn has_balance(&self, now: Instant) -> bool {
        let mut state = self.lock();
        self.settle(&mut state, now);
        state.balance > 0.0
    }

    /// Charge bytes without a lock.
    pub fn debit(&self, amount: u64) {
        if amount > 0 {
            self.pending_debit.fetch_add(amount, Ordering::AcqRel);
        }
    }

    /// Time until the next admission can succeed.
    pub fn retry_after(&self, now: Instant) -> Duration {
        let mut state = self.lock();
        self.settle(&mut state, now);
        let needed = match self.counter {
            Counter::Requests | Counter::Connections => 1.0 - state.balance,
            Counter::BytesOut | Counter::BytesIn => -state.balance + 1.0,
        };
        if needed <= 0.0 {
            return Duration::ZERO;
        }
        let rate = self.capacity() / self.counter.period().as_secs_f64();
        if rate <= 0.0 {
            return self.counter.period();
        }
        Duration::from_secs_f64((needed / rate).min(self.counter.period().as_secs_f64()))
    }

    /// Change the capacity and clamp the balance to it.
    fn reconfigure(&self, capacity: u64, now: Instant) {
        let mut state = self.lock();
        self.settle(&mut state, now);
        self.capacity.store(capacity, Ordering::Relaxed);
        #[allow(clippy::cast_precision_loss)]
        let capacity = capacity as f64;
        state.balance = state.balance.min(capacity);
    }

    #[cfg(test)]
    pub fn balance(&self, now: Instant) -> f64 {
        let mut state = self.lock();
        self.settle(&mut state, now);
        state.balance
    }
}

/// Selectors and ceilings of one budget, from policy.
#[derive(Debug, Clone)]
pub struct BudgetSpec {
    pub name: String,
    pub policies: Vec<String>,
    pub hosts: Vec<HostPattern>,
    pub deny: bool,
    pub requests_per_minute: Option<u64>,
    pub connections_per_minute: Option<u64>,
    pub bytes_out_per_hour: Option<u64>,
    pub bytes_in_per_hour: Option<u64>,
}

impl BudgetSpec {
    fn capacity(&self, counter: Counter) -> Option<u64> {
        match counter {
            Counter::Requests => self.requests_per_minute,
            Counter::Connections => self.connections_per_minute,
            Counter::BytesOut => self.bytes_out_per_hour,
            Counter::BytesIn => self.bytes_in_per_hour,
        }
    }

    /// Whether this budget selects traffic with these authorizing policies and host.
    pub fn selects(&self, authorizing_policies: &[String], host: &str) -> bool {
        let policy_match = self.policies.is_empty()
            || self
                .policies
                .iter()
                .any(|policy| authorizing_policies.iter().any(|name| name == policy));
        let host_match =
            self.hosts.is_empty() || self.hosts.iter().any(|pattern| pattern.matches(host));
        policy_match && host_match
    }
}

/// Live state of one budget.
#[derive(Debug)]
pub struct BudgetEntry {
    pub spec: BudgetSpec,
    requests: Option<Arc<TokenBucket>>,
    connections: Option<Arc<TokenBucket>>,
    bytes_out: Option<Arc<TokenBucket>>,
    bytes_in: Option<Arc<TokenBucket>>,
}

impl BudgetEntry {
    pub fn bucket(&self, counter: Counter) -> Option<&Arc<TokenBucket>> {
        match counter {
            Counter::Requests => self.requests.as_ref(),
            Counter::Connections => self.connections.as_ref(),
            Counter::BytesOut => self.bytes_out.as_ref(),
            Counter::BytesIn => self.bytes_in.as_ref(),
        }
    }
}

/// Budgets keyed by name. Reconciliation keeps the balance of a budget whose
/// name does not change.
#[derive(Debug, Default)]
pub struct BudgetLedger {
    budgets: RwLock<BTreeMap<String, Arc<BudgetEntry>>>,
}

impl BudgetLedger {
    /// Replace the budget set. A kept budget keeps its buckets, clamped to
    /// the new capacity. A removed budget loses its state. A new budget, or a
    /// new counter on a kept budget, starts full.
    pub fn reconcile(&self, specs: Vec<BudgetSpec>, now: Instant) {
        let mut budgets = self
            .budgets
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut next = BTreeMap::new();
        for spec in specs {
            let previous = budgets.get(&spec.name);
            let bucket = |counter: Counter| -> Option<Arc<TokenBucket>> {
                let capacity = spec.capacity(counter)?;
                if let Some(existing) = previous.and_then(|entry| entry.bucket(counter)) {
                    existing.reconfigure(capacity, now);
                    return Some(existing.clone());
                }
                Some(Arc::new(TokenBucket::new(counter, capacity, now)))
            };
            let entry = BudgetEntry {
                requests: bucket(Counter::Requests),
                connections: bucket(Counter::Connections),
                bytes_out: bucket(Counter::BytesOut),
                bytes_in: bucket(Counter::BytesIn),
                spec,
            };
            next.insert(entry.spec.name.clone(), Arc::new(entry));
        }
        *budgets = next;
    }

    /// Budgets that select this traffic, in name order.
    pub fn selected(&self, authorizing_policies: &[String], host: &str) -> Vec<Arc<BudgetEntry>> {
        self.budgets
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|entry| entry.spec.selects(authorizing_policies, host))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, requests_per_minute: Option<u64>) -> BudgetSpec {
        BudgetSpec {
            name: name.to_string(),
            policies: vec![],
            hosts: vec![],
            deny: true,
            requests_per_minute,
            connections_per_minute: None,
            bytes_out_per_hour: None,
            bytes_in_per_hour: None,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn count_bucket_takes_whole_tokens_and_refills() {
        let now = Instant::now();
        let bucket = TokenBucket::new(Counter::Requests, 2, now);
        assert!(bucket.try_take_one(now));
        assert!(bucket.try_take_one(now));
        assert!(!bucket.try_take_one(now));
        // Half a period refills one token for a capacity of two.
        tokio::time::advance(Duration::from_secs(30)).await;
        let later = Instant::now();
        assert!(bucket.try_take_one(later));
        assert!(!bucket.try_take_one(later));
    }

    #[tokio::test(start_paused = true)]
    async fn refill_never_exceeds_capacity() {
        let now = Instant::now();
        let bucket = TokenBucket::new(Counter::Requests, 3, now);
        tokio::time::advance(Duration::from_hours(1)).await;
        assert!((bucket.balance(Instant::now()) - 3.0).abs() < f64::EPSILON);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_bucket_goes_into_debt_and_pays_back() {
        let now = Instant::now();
        let bucket = TokenBucket::new(Counter::BytesIn, 3600, now);
        assert!(bucket.has_balance(now));
        bucket.debit(7200);
        assert!(!bucket.has_balance(now));
        // Debt of 3600 at a refill of one byte per second.
        let wait = bucket.retry_after(now);
        assert!(wait >= Duration::from_hours(1), "{wait:?}");
        tokio::time::advance(Duration::from_secs(3601)).await;
        assert!(bucket.has_balance(Instant::now()));
    }

    #[tokio::test(start_paused = true)]
    async fn force_take_reports_empty_bucket_and_goes_negative() {
        let now = Instant::now();
        let bucket = TokenBucket::new(Counter::Connections, 1, now);
        assert!(bucket.force_take_one(now));
        assert!(!bucket.force_take_one(now));
        assert!(bucket.balance(now) < 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_takes_never_share_the_last_token() {
        let now = Instant::now();
        let bucket = Arc::new(TokenBucket::new(Counter::Requests, 50, now));
        let taken = std::thread::scope(|scope| {
            #[allow(
                clippy::needless_collect,
                reason = "spawn every thread before joining any"
            )]
            let handles: Vec<_> = (0..200)
                .map(|_| scope.spawn(|| bucket.try_take_one(now)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|taken| *taken)
                .count()
        });
        assert_eq!(taken, 50);
    }

    #[tokio::test(start_paused = true)]
    async fn reconcile_keeps_clamps_removes_and_adds() {
        let ledger = BudgetLedger::default();
        let now = Instant::now();
        ledger.reconcile(vec![spec("kept", Some(10)), spec("removed", Some(5))], now);
        let kept = ledger.selected(&[], "example.com");
        let kept_bucket = kept[0].bucket(Counter::Requests).unwrap().clone();
        for _ in 0..4 {
            assert!(kept_bucket.try_take_one(now));
        }

        // Capacity 3 clamps the remaining balance of 6 to 3.
        ledger.reconcile(vec![spec("kept", Some(3)), spec("added", Some(2))], now);
        let selected = ledger.selected(&[], "example.com");
        let names: Vec<_> = selected
            .iter()
            .map(|entry| entry.spec.name.as_str())
            .collect();
        assert_eq!(names, ["added", "kept"]);
        let kept_after = selected[1].bucket(Counter::Requests).unwrap();
        assert!(Arc::ptr_eq(kept_after, &kept_bucket));
        assert!((kept_after.balance(now) - 3.0).abs() < f64::EPSILON);
        assert!(
            (selected[0].bucket(Counter::Requests).unwrap().balance(now) - 2.0).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn selection_uses_authorizing_policies_and_host_patterns() {
        let mut budget = spec("hub", Some(1));
        budget.policies = vec!["model_hub".to_string()];
        budget.hosts = vec![HostPattern::new("*.example.com").unwrap()];
        assert!(budget.selects(&["a".into(), "model_hub".into()], "api.example.com"));
        assert!(!budget.selects(&["a".into()], "api.example.com"));
        assert!(!budget.selects(&["model_hub".into()], "example.org"));
    }
}
