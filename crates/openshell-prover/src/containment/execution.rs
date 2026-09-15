// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configuration containment, assuming the same image identity resolution and
//! execution environment. This does not attest successful Landlock installation.

use super::{
    CheckResult, ContainmentPolicy, Counterexample, ExceedsEvidence, ReasonCode, unsupported,
};
use serde::Deserialize;
use serde_yml::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(super) struct ProcessPolicy {
    #[serde(default)]
    run_as_user: String,
    #[serde(default)]
    run_as_group: String,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Compatibility {
    #[default]
    BestEffort,
    HardRequirement,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
pub(super) struct LandlockPolicy {
    #[serde(default)]
    compatibility: Compatibility,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

pub(super) fn unsupported_reason(policy: &ContainmentPolicy) -> Option<String> {
    if let Some(process) = &policy.process {
        if !process.extra.is_empty() {
            return Some("uses unsupported process fields".to_owned());
        }
        for identity in [&process.run_as_user, &process.run_as_group] {
            // Omission remains unresolved: Docker/Podman may use OCI Config.User.
            // Only runtime-supported sandbox identities plus root (to diagnose
            // escalation) are understood; arbitrary account names are not.
            if !identity.is_empty()
                && !matches!(identity.as_str(), "sandbox" | "root" | "0")
                && !identity
                    .parse::<u32>()
                    .is_ok_and(|id| (1..u32::MAX).contains(&id))
            {
                return Some(format!("uses unsupported process identity '{identity}'"));
            }
        }
    }
    if policy
        .landlock
        .as_ref()
        .is_some_and(|p| !p.extra.is_empty())
    {
        return Some("uses unsupported Landlock fields".to_owned());
    }
    None
}

pub(super) fn check(
    maximum: &ContainmentPolicy,
    candidate: &ContainmentPolicy,
) -> Option<CheckResult> {
    let maximum_process = maximum.process.clone().unwrap_or_default();
    let candidate_process = candidate.process.clone().unwrap_or_default();
    for (field, maximum, candidate) in [
        (
            "run_as_user",
            &maximum_process.run_as_user,
            &candidate_process.run_as_user,
        ),
        (
            "run_as_group",
            &maximum_process.run_as_group,
            &candidate_process.run_as_group,
        ),
    ] {
        if maximum == candidate {
            continue;
        }
        let root = |identity: &str| matches!(identity, "root" | "0");
        if root(maximum) && root(candidate) {
            continue;
        }
        if !maximum.is_empty() && !root(maximum) && root(candidate) {
            return Some(CheckResult::Exceeds(ExceedsEvidence(
                Counterexample::Process {
                    field,
                    maximum: maximum.clone(),
                    candidate: candidate.clone(),
                },
            )));
        }
        return Some(unsupported(
            ReasonCode::UnsupportedPolicyShape,
            format!(
                "process {field} changes from '{maximum}' to '{candidate}'; identity resolution and ordering require execution-environment evidence"
            ),
        ));
    }
    let maximum_landlock = maximum.landlock.clone().unwrap_or_default();
    let candidate_landlock = candidate.landlock.clone().unwrap_or_default();
    if maximum_landlock.compatibility == Compatibility::HardRequirement
        && candidate_landlock.compatibility == Compatibility::BestEffort
    {
        return Some(CheckResult::Exceeds(ExceedsEvidence(
            Counterexample::Landlock {
                maximum: "hard_requirement".to_owned(),
                candidate: "best_effort".to_owned(),
            },
        )));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containment::{CheckOptions, check_within_maximum, parse_policy_str};

    fn result(maximum: &str, candidate: &str) -> CheckResult {
        check_within_maximum(
            &parse_policy_str(&format!("version: 1\n{maximum}")).unwrap(),
            &parse_policy_str(&format!("version: 1\n{candidate}")).unwrap(),
            CheckOptions {
                timeout: std::time::Duration::from_secs(10),
            },
        )
    }

    #[test]
    fn process_matches_and_root_escalations() {
        let sandbox = "process: {run_as_user: sandbox, run_as_group: sandbox}";
        assert!(matches!(result(sandbox, sandbox), CheckResult::Within(_)));
        for candidate in [
            "process: {run_as_user: root, run_as_group: sandbox}",
            "process: {run_as_user: sandbox, run_as_group: '0'}",
        ] {
            assert!(matches!(
                result(sandbox, candidate),
                CheckResult::Exceeds(_)
            ));
        }
        for candidate in [
            "process: {run_as_user: '1001', run_as_group: sandbox}",
            "process: {}",
            "",
        ] {
            assert!(matches!(
                result(sandbox, candidate),
                CheckResult::Unsupported(_)
            ));
        }
        assert!(matches!(result("", sandbox), CheckResult::Unsupported(_)));
    }

    #[test]
    fn landlock_compatibility_and_defaults() {
        let hard = "landlock: {compatibility: hard_requirement}";
        for soft in ["", "landlock: {}", "landlock: {compatibility: best_effort}"] {
            assert!(matches!(result(soft, hard), CheckResult::Within(_)));
            assert!(matches!(result(hard, soft), CheckResult::Exceeds(_)));
            assert!(matches!(result(soft, soft), CheckResult::Within(_)));
        }
        assert!(matches!(result(hard, hard), CheckResult::Within(_)));
    }

    #[test]
    fn unknown_fields_and_identities_fail_closed() {
        for policy in [
            "process: {capabilities: all}",
            "landlock: {disabled: true}",
            "process: {run_as_user: nobody}",
        ] {
            assert!(matches!(
                result(policy, policy),
                CheckResult::Unsupported(_)
            ));
        }
        assert!(parse_policy_str("version: 1\nlandlock: {compatibility: disabled}").is_err());
    }
}
