// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! First-use tracking of hosts, binaries, and rule IDs per policy key.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::Duration;

use openshell_core::egress_usage::{MAX_NOVELTY_ITEMS, MAX_NOVELTY_ITEMS_PER_KIND};
use tokio::time::Instant;

/// Kinds of novelty items.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoveltyKind {
    Host,
    Binary,
    Rule,
}

impl NoveltyKind {
    pub const fn finding_type(self) -> &'static str {
        match self {
            Self::Host => "egress.new_host",
            Self::Binary => "egress.new_binary",
            Self::Rule => "egress.new_rule",
        }
    }
}

/// Result of one novelty observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// The item was already known, or was learned during the learning period.
    Known,
    /// First use after the learning period.
    New,
    /// The set is full and the item was not recorded. Reported once per set.
    Saturated,
}

#[derive(Debug)]
struct PolicyNovelty {
    learning_started: Instant,
    endpoint_ids: BTreeSet<String>,
    items: [HashSet<String>; 3],
    saturated: [bool; 3],
}

const fn kind_index(kind: NoveltyKind) -> usize {
    match kind {
        NoveltyKind::Host => 0,
        NoveltyKind::Binary => 1,
        NoveltyKind::Rule => 2,
    }
}

/// Novelty sets for every policy key of one sandbox.
#[derive(Debug)]
pub struct Novelty {
    learning_period: Duration,
    policies: BTreeMap<String, PolicyNovelty>,
    total_items: usize,
}

impl Novelty {
    pub fn new(learning_period: Duration) -> Self {
        Self {
            learning_period,
            policies: BTreeMap::new(),
            total_items: 0,
        }
    }

    /// Apply a new policy. The learning period of a policy key starts again
    /// only when its set of endpoint IDs changes. Items stay after a restart.
    pub fn reconfigure(
        &mut self,
        learning_period: Duration,
        endpoints_by_policy: &BTreeMap<String, BTreeSet<String>>,
        now: Instant,
    ) {
        self.learning_period = learning_period;
        for (policy_key, endpoint_ids) in endpoints_by_policy {
            match self.policies.get_mut(policy_key) {
                Some(state) if &state.endpoint_ids == endpoint_ids => {}
                Some(state) => {
                    state.endpoint_ids.clone_from(endpoint_ids);
                    state.learning_started = now;
                }
                None => {
                    self.policies.insert(
                        policy_key.clone(),
                        PolicyNovelty {
                            learning_started: now,
                            endpoint_ids: endpoint_ids.clone(),
                            items: Default::default(),
                            saturated: [false; 3],
                        },
                    );
                }
            }
        }
    }

    pub fn observe(
        &mut self,
        policy_key: &str,
        kind: NoveltyKind,
        item: &str,
        now: Instant,
    ) -> Observation {
        if item.is_empty() {
            return Observation::Known;
        }
        let learning_period = self.learning_period;
        let state = self
            .policies
            .entry(policy_key.to_string())
            .or_insert_with(|| PolicyNovelty {
                learning_started: now,
                endpoint_ids: BTreeSet::new(),
                items: Default::default(),
                saturated: [false; 3],
            });
        let index = kind_index(kind);
        if state.items[index].contains(item) {
            return Observation::Known;
        }
        if state.items[index].len() >= MAX_NOVELTY_ITEMS_PER_KIND
            || self.total_items >= MAX_NOVELTY_ITEMS
        {
            if state.saturated[index] {
                return Observation::Known;
            }
            state.saturated[index] = true;
            return Observation::Saturated;
        }
        state.items[index].insert(item.to_string());
        self.total_items += 1;
        if now.saturating_duration_since(state.learning_started) < learning_period {
            Observation::Known
        } else {
            Observation::New
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoints(ids: &[&str]) -> BTreeMap<String, BTreeSet<String>> {
        BTreeMap::from([(
            "api".to_string(),
            ids.iter().map(|id| (*id).to_string()).collect(),
        )])
    }

    #[tokio::test(start_paused = true)]
    async fn items_learned_during_learning_period_produce_no_finding() {
        let mut novelty = Novelty::new(Duration::from_mins(1));
        novelty.reconfigure(Duration::from_mins(1), &endpoints(&["e1"]), Instant::now());
        assert_eq!(
            novelty.observe("api", NoveltyKind::Host, "a.example.com", Instant::now()),
            Observation::Known
        );
        tokio::time::advance(Duration::from_secs(61)).await;
        assert_eq!(
            novelty.observe("api", NoveltyKind::Host, "a.example.com", Instant::now()),
            Observation::Known
        );
        assert_eq!(
            novelty.observe("api", NoveltyKind::Host, "b.example.com", Instant::now()),
            Observation::New
        );
        assert_eq!(
            novelty.observe("api", NoveltyKind::Host, "b.example.com", Instant::now()),
            Observation::Known
        );
    }

    #[tokio::test(start_paused = true)]
    async fn learning_restarts_only_when_endpoints_change() {
        let mut novelty = Novelty::new(Duration::from_mins(1));
        novelty.reconfigure(Duration::from_mins(1), &endpoints(&["e1"]), Instant::now());
        tokio::time::advance(Duration::from_secs(61)).await;

        novelty.reconfigure(Duration::from_mins(1), &endpoints(&["e1"]), Instant::now());
        assert_eq!(
            novelty.observe("api", NoveltyKind::Binary, "sha-a", Instant::now()),
            Observation::New
        );

        novelty.reconfigure(
            Duration::from_mins(1),
            &endpoints(&["e1", "e2"]),
            Instant::now(),
        );
        assert_eq!(
            novelty.observe("api", NoveltyKind::Binary, "sha-b", Instant::now()),
            Observation::Known
        );
    }

    #[tokio::test(start_paused = true)]
    async fn full_set_reports_saturation_once() {
        let mut novelty = Novelty::new(Duration::ZERO);
        let now = Instant::now();
        for index in 0..MAX_NOVELTY_ITEMS_PER_KIND {
            novelty.observe("api", NoveltyKind::Rule, &format!("rule:{index}"), now);
        }
        assert_eq!(
            novelty.observe("api", NoveltyKind::Rule, "rule:new", now),
            Observation::Saturated
        );
        assert_eq!(
            novelty.observe("api", NoveltyKind::Rule, "rule:new-2", now),
            Observation::Known
        );
    }
}
