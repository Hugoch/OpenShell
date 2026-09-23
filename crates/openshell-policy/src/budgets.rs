// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! YAML schema and protobuf conversion for egress usage budgets and usage
//! monitoring settings.

use std::collections::{BTreeMap, HashMap};

use openshell_core::egress_usage::{MAX_BUDGET_HOST_PATTERNS, MAX_NETWORK_BUDGETS};
use openshell_core::host_pattern::HostPattern;
use openshell_core::proto::{
    NetworkBudget, NetworkBudgetAction, SandboxPolicy, UsageDrift, UsageMonitoring, UsageNovelty,
};
use openshell_policy_schema::{
    NetworkBudget as NetworkBudgetDef, NetworkBudgetAction as NetworkBudgetActionDef,
    UsageDrift as UsageDriftDef, UsageMonitoring as UsageMonitoringDef,
    UsageNovelty as UsageNoveltyDef,
};

use super::PolicyViolation;

pub fn into_proto(
    definitions: BTreeMap<String, NetworkBudgetDef>,
) -> HashMap<String, NetworkBudget> {
    definitions
        .into_iter()
        .map(|(name, definition)| {
            let on_exceed = match definition.on_exceed {
                NetworkBudgetActionDef::Alert => NetworkBudgetAction::Alert,
                NetworkBudgetActionDef::Deny => NetworkBudgetAction::Deny,
            };
            (
                name,
                NetworkBudget {
                    policies: definition.policies,
                    hosts: definition.hosts,
                    requests_per_minute: definition.requests_per_minute,
                    connections_per_minute: definition.connections_per_minute,
                    bytes_out_per_hour: definition.bytes_out_per_hour,
                    bytes_in_per_hour: definition.bytes_in_per_hour,
                    on_exceed: on_exceed as i32,
                },
            )
        })
        .collect()
}

pub fn from_proto(budgets: &HashMap<String, NetworkBudget>) -> BTreeMap<String, NetworkBudgetDef> {
    budgets
        .iter()
        .map(|(name, budget)| {
            let on_exceed = if budget.on_exceed == NetworkBudgetAction::Deny as i32 {
                NetworkBudgetActionDef::Deny
            } else {
                NetworkBudgetActionDef::Alert
            };
            (
                name.clone(),
                NetworkBudgetDef {
                    policies: budget.policies.clone(),
                    hosts: budget.hosts.clone(),
                    requests_per_minute: budget.requests_per_minute,
                    connections_per_minute: budget.connections_per_minute,
                    bytes_out_per_hour: budget.bytes_out_per_hour,
                    bytes_in_per_hour: budget.bytes_in_per_hour,
                    on_exceed,
                },
            )
        })
        .collect()
}

pub fn monitoring_into_proto(monitoring: UsageMonitoringDef) -> UsageMonitoring {
    UsageMonitoring {
        novelty: monitoring.novelty.map(|novelty| UsageNovelty {
            learning_period: novelty
                .learning_period_seconds
                .map(|seconds| prost_types::Duration {
                    seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
                    nanos: 0,
                }),
        }),
        drift: monitoring.drift.map(|drift| UsageDrift {
            enabled: drift.enabled,
            ratio: drift.ratio,
            min_requests: drift.min_requests,
            min_bytes: drift.min_bytes,
        }),
    }
}

pub fn monitoring_from_proto(monitoring: &UsageMonitoring) -> UsageMonitoringDef {
    UsageMonitoringDef {
        novelty: monitoring.novelty.as_ref().map(|novelty| UsageNoveltyDef {
            learning_period_seconds: novelty
                .learning_period
                .as_ref()
                .map(|duration| u64::try_from(duration.seconds).unwrap_or(0)),
        }),
        drift: monitoring.drift.as_ref().map(|drift| UsageDriftDef {
            enabled: drift.enabled,
            ratio: drift.ratio,
            min_requests: drift.min_requests,
            min_bytes: drift.min_bytes,
        }),
    }
}

pub fn validate(policy: &SandboxPolicy) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();
    if policy.network_budgets.len() > MAX_NETWORK_BUDGETS {
        violations.push(PolicyViolation::TooManyNetworkBudgets {
            count: policy.network_budgets.len(),
        });
    }

    let mut budgets: Vec<_> = policy.network_budgets.iter().collect();
    budgets.sort_by_key(|(name, _)| name.as_str());
    for (name, budget) in budgets {
        let mut invalid = |reason: String| {
            violations.push(PolicyViolation::InvalidNetworkBudget {
                name: name.clone(),
                reason,
            });
        };
        if name.is_empty() {
            invalid("name must not be empty".to_string());
        }
        let counters = [
            ("requests_per_minute", budget.requests_per_minute),
            ("connections_per_minute", budget.connections_per_minute),
            ("bytes_out_per_hour", budget.bytes_out_per_hour),
            ("bytes_in_per_hour", budget.bytes_in_per_hour),
        ];
        if counters.iter().all(|(_, value)| value.is_none()) {
            invalid("at least one counter is required".to_string());
        }
        for (counter, value) in counters {
            if value == Some(0) {
                invalid(format!(
                    "{counter} must be more than zero; remove the endpoint to block it"
                ));
            }
        }
        if NetworkBudgetAction::try_from(budget.on_exceed).is_err() {
            invalid(format!("invalid on_exceed value {}", budget.on_exceed));
        }
        for policy_key in &budget.policies {
            if !policy.network_policies.contains_key(policy_key) {
                invalid(format!("policy '{policy_key}' is not a network policy key"));
            }
        }
        if budget.hosts.len() > MAX_BUDGET_HOST_PATTERNS {
            invalid(format!(
                "too many host patterns ({} > {MAX_BUDGET_HOST_PATTERNS})",
                budget.hosts.len()
            ));
        }
        for pattern in &budget.hosts {
            if let Err(reason) = HostPattern::new(pattern) {
                invalid(format!("host pattern '{pattern}' is invalid: {reason}"));
            }
        }
    }

    if let Some(drift) = policy
        .usage_monitoring
        .as_ref()
        .and_then(|monitoring| monitoring.drift.as_ref())
        && drift.ratio.is_some_and(|ratio| ratio < 2)
    {
        violations.push(PolicyViolation::InvalidUsageMonitoring {
            reason: "drift.ratio must be at least 2".to_string(),
        });
    }
    if let Some(learning_period) = policy
        .usage_monitoring
        .as_ref()
        .and_then(|monitoring| monitoring.novelty.as_ref())
        .and_then(|novelty| novelty.learning_period.as_ref())
        && (learning_period.seconds < 0 || learning_period.nanos < 0)
    {
        violations.push(PolicyViolation::InvalidUsageMonitoring {
            reason: "novelty.learning_period must not be negative".to_string(),
        });
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::NetworkPolicyRule;

    fn policy_with_budget(budget: NetworkBudget) -> SandboxPolicy {
        SandboxPolicy {
            network_policies: HashMap::from([(
                "model_hub".to_string(),
                NetworkPolicyRule::default(),
            )]),
            network_budgets: HashMap::from([("hub".to_string(), budget)]),
            ..Default::default()
        }
    }

    #[test]
    fn valid_budget_has_no_violations() {
        let policy = policy_with_budget(NetworkBudget {
            policies: vec!["model_hub".to_string()],
            hosts: vec!["*.huggingface.co".to_string()],
            requests_per_minute: Some(10),
            on_exceed: NetworkBudgetAction::Deny as i32,
            ..Default::default()
        });
        assert!(validate(&policy).is_empty(), "{:?}", validate(&policy));
    }

    #[test]
    fn rejects_zero_counter_unknown_policy_and_empty_budget() {
        let zero = policy_with_budget(NetworkBudget {
            requests_per_minute: Some(0),
            ..Default::default()
        });
        assert!(
            validate(&zero)
                .iter()
                .any(|violation| violation.to_string().contains("more than zero"))
        );

        let unknown = policy_with_budget(NetworkBudget {
            policies: vec!["missing".to_string()],
            requests_per_minute: Some(1),
            ..Default::default()
        });
        assert!(
            validate(&unknown)
                .iter()
                .any(|violation| violation.to_string().contains("'missing'"))
        );

        let empty = policy_with_budget(NetworkBudget::default());
        assert!(
            validate(&empty)
                .iter()
                .any(|violation| violation.to_string().contains("at least one counter"))
        );
    }

    #[test]
    fn rejects_too_many_budgets() {
        let mut policy = SandboxPolicy::default();
        for index in 0..=MAX_NETWORK_BUDGETS {
            policy.network_budgets.insert(
                format!("b{index}"),
                NetworkBudget {
                    requests_per_minute: Some(1),
                    ..Default::default()
                },
            );
        }
        assert!(
            validate(&policy).iter().any(|violation| matches!(
                violation,
                PolicyViolation::TooManyNetworkBudgets { .. }
            ))
        );
    }

    #[test]
    fn budgets_round_trip_through_proto() {
        let definitions = BTreeMap::from([(
            "hub".to_string(),
            NetworkBudgetDef {
                policies: vec!["model_hub".to_string()],
                hosts: vec![],
                requests_per_minute: Some(5),
                connections_per_minute: None,
                bytes_out_per_hour: None,
                bytes_in_per_hour: Some(1024),
                on_exceed: NetworkBudgetActionDef::Deny,
            },
        )]);
        let proto = into_proto(definitions.clone());
        assert_eq!(from_proto(&proto), definitions);
    }
}
