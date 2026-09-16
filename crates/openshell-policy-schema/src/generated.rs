// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use miette::{IntoDiagnostic, Result, WrapErr};
use prost_types::{ListValue, Struct, Value, value};

use crate::proto;
use crate::{
    AnyMatcher, FilesystemPolicy, GraphqlOperation, JsonRpcConfig, L7Allow, L7DenyRule, L7Rule,
    LandlockCompatibility, LandlockPolicy, McpConfig, MiddlewareEndpointSelector, NetworkBinary,
    NetworkCredentialBinding, NetworkEndpoint, NetworkMiddleware, NetworkPolicyRule,
    ParameterMatcher, ParseLimits, PolicyDocument, ProcessPolicy, QueryMatcher,
};

/// Parse compatible policy YAML into the generated public message.
pub fn parse_policy_proto(source: &str) -> Result<proto::SandboxPolicy> {
    crate::parse_policy(source)?.try_into()
}

/// Parse a compatible policy YAML file into the generated public message.
pub fn parse_policy_proto_file(path: &Path, limits: ParseLimits) -> Result<proto::SandboxPolicy> {
    crate::parse_policy_file(path, limits)?.try_into()
}

/// Validate a generated public policy with the schema-owned intrinsic checks.
pub fn validate_authored_policy(policy: &proto::SandboxPolicy) -> Result<()> {
    let document = PolicyDocument::try_from(policy.clone())?;
    crate::validate_policy(&document)
}

/// Serialize a generated public policy using the canonical authored YAML form.
pub fn serialize_policy_proto(policy: &proto::SandboxPolicy) -> Result<String> {
    let document = PolicyDocument::try_from(policy.clone())?;
    crate::validate_policy(&document)?;
    crate::serialize_policy(&document)
}

/// Convert a generated public policy to canonical authored JSON.
pub fn policy_proto_to_json_value(policy: &proto::SandboxPolicy) -> Result<serde_json::Value> {
    let document = PolicyDocument::try_from(policy.clone())?;
    crate::validate_policy(&document)?;
    crate::policy_to_json_value(&document)
}

impl TryFrom<PolicyDocument> for proto::SandboxPolicy {
    type Error = miette::Report;

    fn try_from(document: PolicyDocument) -> Result<Self> {
        crate::validate_policy(&document)?;
        Ok(Self {
            version: document.version,
            filesystem_policy: document.filesystem_policy.map(Into::into),
            landlock: document.landlock.map(Into::into),
            process: document.process.map(Into::into),
            network_policies: document
                .network_policies
                .into_iter()
                .map(|(name, rule)| Ok((name, rule.try_into()?)))
                .collect::<Result<HashMap<_, _>>>()?,
            network_middlewares: document
                .network_middlewares
                .into_iter()
                .map(|(name, middleware)| Ok((name, middleware.try_into()?)))
                .collect::<Result<HashMap<_, _>>>()?,
        })
    }
}

impl TryFrom<proto::SandboxPolicy> for PolicyDocument {
    type Error = miette::Report;

    fn try_from(policy: proto::SandboxPolicy) -> Result<Self> {
        let document = Self {
            version: policy.version,
            filesystem_policy: policy.filesystem_policy.map(Into::into),
            landlock: policy.landlock.map(TryInto::try_into).transpose()?,
            process: policy.process.map(Into::into),
            network_policies: policy
                .network_policies
                .into_iter()
                .map(|(name, rule)| Ok((name, rule.try_into()?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
            network_middlewares: policy
                .network_middlewares
                .into_iter()
                .map(|(name, middleware)| Ok((name, middleware.try_into()?)))
                .collect::<Result<BTreeMap<_, _>>>()?,
        };
        crate::validate_policy(&document)?;
        Ok(document)
    }
}

impl From<FilesystemPolicy> for proto::FilesystemPolicy {
    fn from(policy: FilesystemPolicy) -> Self {
        Self {
            include_workdir: policy.include_workdir,
            read_only: policy.read_only,
            read_write: policy.read_write,
        }
    }
}

impl From<proto::FilesystemPolicy> for FilesystemPolicy {
    fn from(policy: proto::FilesystemPolicy) -> Self {
        Self {
            include_workdir: policy.include_workdir,
            read_only: policy.read_only,
            read_write: policy.read_write,
        }
    }
}

impl From<LandlockPolicy> for proto::LandlockPolicy {
    fn from(policy: LandlockPolicy) -> Self {
        let compatibility = match policy.compatibility {
            LandlockCompatibility::BestEffort => "best_effort",
            LandlockCompatibility::HardRequirement => "hard_requirement",
        };
        Self {
            compatibility: compatibility.to_string(),
        }
    }
}

impl TryFrom<proto::LandlockPolicy> for LandlockPolicy {
    type Error = miette::Report;

    fn try_from(policy: proto::LandlockPolicy) -> Result<Self> {
        let compatibility = match policy.compatibility.as_str() {
            "" | "best_effort" => LandlockCompatibility::BestEffort,
            "hard_requirement" => LandlockCompatibility::HardRequirement,
            value => miette::bail!(
                "invalid landlock.compatibility '{value}'; expected best_effort or hard_requirement"
            ),
        };
        Ok(Self { compatibility })
    }
}

impl From<ProcessPolicy> for proto::ProcessPolicy {
    fn from(policy: ProcessPolicy) -> Self {
        Self {
            run_as_user: policy.run_as_user,
            run_as_group: policy.run_as_group,
        }
    }
}

impl From<proto::ProcessPolicy> for ProcessPolicy {
    fn from(policy: proto::ProcessPolicy) -> Self {
        Self {
            run_as_user: policy.run_as_user,
            run_as_group: policy.run_as_group,
        }
    }
}

impl TryFrom<NetworkPolicyRule> for proto::NetworkPolicyRule {
    type Error = miette::Report;

    fn try_from(rule: NetworkPolicyRule) -> Result<Self> {
        Ok(Self {
            name: rule.name,
            endpoints: rule
                .endpoints
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            binaries: rule.binaries.into_iter().map(Into::into).collect(),
        })
    }
}

impl TryFrom<proto::NetworkPolicyRule> for NetworkPolicyRule {
    type Error = miette::Report;

    fn try_from(rule: proto::NetworkPolicyRule) -> Result<Self> {
        Ok(Self {
            name: rule.name,
            endpoints: rule
                .endpoints
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            binaries: rule.binaries.into_iter().map(Into::into).collect(),
        })
    }
}

impl TryFrom<NetworkEndpoint> for proto::NetworkEndpoint {
    type Error = miette::Report;

    fn try_from(endpoint: NetworkEndpoint) -> Result<Self> {
        Ok(Self {
            host: endpoint.host,
            path: endpoint.path,
            port: u32::from(endpoint.port),
            ports: endpoint.ports.into_iter().map(u32::from).collect(),
            protocol: endpoint.protocol,
            tls: endpoint.tls,
            enforcement: endpoint.enforcement,
            access: endpoint.access,
            rules: endpoint
                .rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allowed_ips: endpoint.allowed_ips,
            deny_rules: endpoint
                .deny_rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allow_encoded_slash: endpoint.allow_encoded_slash,
            websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
            request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
            allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
            persisted_queries: endpoint.persisted_queries,
            graphql_persisted_queries: endpoint
                .graphql_persisted_queries
                .into_iter()
                .map(|(name, operation)| (name, operation.into()))
                .collect(),
            graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
            credential_signing: endpoint.credential_signing,
            signing_service: endpoint.signing_service,
            signing_region: endpoint.signing_region,
            credential_binding: endpoint.credential_binding.map(Into::into),
            json_rpc: endpoint.json_rpc.map(Into::into),
            mcp: endpoint.mcp.map(Into::into),
        })
    }
}

impl TryFrom<proto::NetworkEndpoint> for NetworkEndpoint {
    type Error = miette::Report;

    fn try_from(endpoint: proto::NetworkEndpoint) -> Result<Self> {
        Ok(Self {
            host: endpoint.host,
            path: endpoint.path,
            port: u16::try_from(endpoint.port)
                .into_diagnostic()
                .wrap_err("endpoint.port must be in 0..=65535")?,
            ports: endpoint
                .ports
                .into_iter()
                .map(|port| {
                    u16::try_from(port)
                        .into_diagnostic()
                        .wrap_err("endpoint.ports values must be in 0..=65535")
                })
                .collect::<Result<_>>()?,
            protocol: endpoint.protocol,
            tls: endpoint.tls,
            enforcement: endpoint.enforcement,
            access: endpoint.access,
            rules: endpoint
                .rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allowed_ips: endpoint.allowed_ips,
            deny_rules: endpoint
                .deny_rules
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_>>()?,
            allow_encoded_slash: endpoint.allow_encoded_slash,
            websocket_credential_rewrite: endpoint.websocket_credential_rewrite,
            request_body_credential_rewrite: endpoint.request_body_credential_rewrite,
            allow_uninspected_credentials: endpoint.allow_uninspected_credentials,
            persisted_queries: endpoint.persisted_queries,
            graphql_persisted_queries: endpoint
                .graphql_persisted_queries
                .into_iter()
                .map(|(name, operation)| (name, operation.into()))
                .collect(),
            graphql_max_body_bytes: endpoint.graphql_max_body_bytes,
            credential_signing: endpoint.credential_signing,
            signing_service: endpoint.signing_service,
            signing_region: endpoint.signing_region,
            credential_binding: endpoint.credential_binding.map(Into::into),
            json_rpc: endpoint.json_rpc.map(Into::into),
            mcp: endpoint.mcp.map(Into::into),
        })
    }
}

impl From<NetworkCredentialBinding> for proto::NetworkCredentialBinding {
    fn from(binding: NetworkCredentialBinding) -> Self {
        Self {
            provider: binding.provider,
        }
    }
}

impl From<proto::NetworkCredentialBinding> for NetworkCredentialBinding {
    fn from(binding: proto::NetworkCredentialBinding) -> Self {
        Self {
            provider: binding.provider,
        }
    }
}

impl From<JsonRpcConfig> for proto::JsonRpcConfig {
    fn from(config: JsonRpcConfig) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
        }
    }
}

impl From<proto::JsonRpcConfig> for JsonRpcConfig {
    fn from(config: proto::JsonRpcConfig) -> Self {
        Self {
            max_body_bytes: config.max_body_bytes,
        }
    }
}

impl From<McpConfig> for proto::McpConfig {
    fn from(config: McpConfig) -> Self {
        Self {
            versions: config.versions.map(|values| proto::McpVersions { values }),
            max_body_bytes: config.max_body_bytes,
            strict_tool_names: config.strict_tool_names,
            allow_all_known_mcp_methods: config.allow_all_known_mcp_methods,
        }
    }
}

impl From<proto::McpConfig> for McpConfig {
    fn from(config: proto::McpConfig) -> Self {
        Self {
            versions: config.versions.map(|versions| versions.values),
            max_body_bytes: config.max_body_bytes,
            strict_tool_names: config.strict_tool_names,
            allow_all_known_mcp_methods: config.allow_all_known_mcp_methods,
        }
    }
}

impl From<GraphqlOperation> for proto::GraphqlOperation {
    fn from(operation: GraphqlOperation) -> Self {
        Self {
            operation_type: operation.operation_type,
            operation_name: operation.operation_name,
            fields: operation.fields,
        }
    }
}

impl From<proto::GraphqlOperation> for GraphqlOperation {
    fn from(operation: proto::GraphqlOperation) -> Self {
        Self {
            operation_type: operation.operation_type,
            operation_name: operation.operation_name,
            fields: operation.fields,
        }
    }
}

impl TryFrom<L7Rule> for proto::L7Rule {
    type Error = miette::Report;

    fn try_from(rule: L7Rule) -> Result<Self> {
        Ok(Self {
            allow: Some(rule.allow.try_into()?),
        })
    }
}

impl TryFrom<proto::L7Rule> for L7Rule {
    type Error = miette::Report;

    fn try_from(rule: proto::L7Rule) -> Result<Self> {
        Ok(Self {
            allow: rule
                .allow
                .ok_or_else(|| miette::miette!("L7Rule.allow is required"))?
                .try_into()?,
        })
    }
}

impl TryFrom<L7Allow> for proto::L7Allow {
    type Error = miette::Report;

    fn try_from(allow: L7Allow) -> Result<Self> {
        Ok(Self {
            method: allow.method,
            path: allow.path,
            command: allow.command,
            query: allow
                .query
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
            operation_type: allow.operation_type,
            operation_name: allow.operation_name,
            fields: allow.fields,
            tool: allow.tool.map(Into::into),
            params: allow
                .params
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
        })
    }
}

impl TryFrom<proto::L7Allow> for L7Allow {
    type Error = miette::Report;

    fn try_from(allow: proto::L7Allow) -> Result<Self> {
        Ok(Self {
            method: allow.method,
            path: allow.path,
            command: allow.command,
            query: allow
                .query
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
            operation_type: allow.operation_type,
            operation_name: allow.operation_name,
            fields: allow.fields,
            tool: allow.tool.map(TryInto::try_into).transpose()?,
            params: allow
                .params
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
        })
    }
}

impl TryFrom<L7DenyRule> for proto::L7DenyRule {
    type Error = miette::Report;

    fn try_from(rule: L7DenyRule) -> Result<Self> {
        Ok(Self {
            method: rule.method,
            path: rule.path,
            command: rule.command,
            query: rule
                .query
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
            operation_type: rule.operation_type,
            operation_name: rule.operation_name,
            fields: rule.fields,
            tool: rule.tool.map(Into::into),
            params: rule
                .params
                .into_iter()
                .map(|(name, matcher)| (name, matcher.into()))
                .collect(),
        })
    }
}

impl TryFrom<proto::L7DenyRule> for L7DenyRule {
    type Error = miette::Report;

    fn try_from(rule: proto::L7DenyRule) -> Result<Self> {
        Ok(Self {
            method: rule.method,
            path: rule.path,
            command: rule.command,
            query: rule
                .query
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
            operation_type: rule.operation_type,
            operation_name: rule.operation_name,
            fields: rule.fields,
            tool: rule.tool.map(TryInto::try_into).transpose()?,
            params: rule
                .params
                .into_iter()
                .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                .collect::<Result<_>>()?,
        })
    }
}

impl From<QueryMatcher> for proto::Matcher {
    fn from(matcher: QueryMatcher) -> Self {
        let kind = match matcher {
            QueryMatcher::Glob(glob) => proto::matcher::Kind::Glob(glob),
            QueryMatcher::Any(any) => {
                proto::matcher::Kind::Any(proto::AnyMatcher { values: any.any })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<proto::Matcher> for QueryMatcher {
    type Error = miette::Report;

    fn try_from(matcher: proto::Matcher) -> Result<Self> {
        match matcher.kind {
            Some(proto::matcher::Kind::Glob(glob)) => Ok(Self::Glob(glob)),
            Some(proto::matcher::Kind::Any(any)) => Ok(Self::Any(AnyMatcher { any: any.values })),
            None => miette::bail!("matcher kind is required"),
        }
    }
}

impl From<ParameterMatcher> for proto::ParameterMatcher {
    fn from(matcher: ParameterMatcher) -> Self {
        let kind = match matcher {
            ParameterMatcher::Matcher(matcher) => {
                proto::parameter_matcher::Kind::Matcher(matcher.into())
            }
            ParameterMatcher::Object(fields) => {
                proto::parameter_matcher::Kind::Object(proto::ParameterObject {
                    fields: fields
                        .into_iter()
                        .map(|(name, matcher)| (name, matcher.into()))
                        .collect(),
                })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<proto::ParameterMatcher> for ParameterMatcher {
    type Error = miette::Report;

    fn try_from(matcher: proto::ParameterMatcher) -> Result<Self> {
        match matcher.kind {
            Some(proto::parameter_matcher::Kind::Matcher(matcher)) => {
                Ok(Self::Matcher(matcher.try_into()?))
            }
            Some(proto::parameter_matcher::Kind::Object(object)) => Ok(Self::Object(
                object
                    .fields
                    .into_iter()
                    .map(|(name, matcher)| Ok((name, matcher.try_into()?)))
                    .collect::<Result<_>>()?,
            )),
            None => miette::bail!("parameter matcher kind is required"),
        }
    }
}

impl From<NetworkBinary> for proto::NetworkBinary {
    fn from(binary: NetworkBinary) -> Self {
        Self { path: binary.path }
    }
}

impl From<proto::NetworkBinary> for NetworkBinary {
    fn from(binary: proto::NetworkBinary) -> Self {
        Self { path: binary.path }
    }
}

impl TryFrom<NetworkMiddleware> for proto::NetworkMiddleware {
    type Error = miette::Report;

    fn try_from(middleware: NetworkMiddleware) -> Result<Self> {
        Ok(Self {
            name: middleware.name,
            middleware: middleware.middleware,
            order: middleware.order,
            config: (!middleware.config.is_empty())
                .then(|| json_object_to_struct(middleware.config))
                .transpose()?,
            on_error: middleware.on_error,
            endpoints: middleware.endpoints.map(Into::into),
        })
    }
}

impl TryFrom<proto::NetworkMiddleware> for NetworkMiddleware {
    type Error = miette::Report;

    fn try_from(middleware: proto::NetworkMiddleware) -> Result<Self> {
        Ok(Self {
            name: middleware.name,
            middleware: middleware.middleware,
            order: middleware.order,
            config: middleware
                .config
                .map(struct_to_json_object)
                .transpose()?
                .unwrap_or_default(),
            on_error: middleware.on_error,
            endpoints: middleware.endpoints.map(Into::into),
        })
    }
}

impl From<MiddlewareEndpointSelector> for proto::MiddlewareEndpointSelector {
    fn from(selector: MiddlewareEndpointSelector) -> Self {
        Self {
            include: selector.include,
            exclude: selector.exclude,
        }
    }
}

impl From<proto::MiddlewareEndpointSelector> for MiddlewareEndpointSelector {
    fn from(selector: proto::MiddlewareEndpointSelector) -> Self {
        Self {
            include: selector.include,
            exclude: selector.exclude,
        }
    }
}

fn json_object_to_struct(config: BTreeMap<String, serde_json::Value>) -> Result<Struct> {
    Ok(Struct {
        fields: config
            .into_iter()
            .map(|(name, value)| Ok((name, json_to_proto_value(value)?)))
            .collect::<Result<_>>()?,
    })
}

fn json_to_proto_value(value: serde_json::Value) -> Result<Value> {
    let kind = match value {
        serde_json::Value::Null => value::Kind::NullValue(0),
        serde_json::Value::Bool(value) => value::Kind::BoolValue(value),
        serde_json::Value::Number(value) => value::Kind::NumberValue(number_to_f64_exact(&value)?),
        serde_json::Value::String(value) => value::Kind::StringValue(value),
        serde_json::Value::Array(values) => value::Kind::ListValue(ListValue {
            values: values
                .into_iter()
                .map(json_to_proto_value)
                .collect::<Result<_>>()?,
        }),
        serde_json::Value::Object(fields) => value::Kind::StructValue(Struct {
            fields: fields
                .into_iter()
                .map(|(name, value)| Ok((name, json_to_proto_value(value)?)))
                .collect::<Result<_>>()?,
        }),
    };
    Ok(Value { kind: Some(kind) })
}

fn number_to_f64_exact(value: &serde_json::Number) -> Result<f64> {
    let number = value.as_f64().ok_or_else(|| {
        miette::miette!(
            "middleware config number {value} is not representable as a protobuf double"
        )
    })?;
    let exact = value.as_i64().map_or_else(
        || value.as_u64().is_none_or(integer_is_exact_in_f64),
        |integer| integer_is_exact_in_f64(integer.unsigned_abs()),
    );
    exact.then_some(number).ok_or_else(|| {
        miette::miette!(
            "middleware config number {value} is not representable exactly as a protobuf double"
        )
    })
}

fn integer_is_exact_in_f64(integer: u64) -> bool {
    integer == 0
        || (u64::BITS - integer.leading_zeros()).saturating_sub(integer.trailing_zeros())
            <= f64::MANTISSA_DIGITS
}

fn struct_to_json_object(config: Struct) -> Result<BTreeMap<String, serde_json::Value>> {
    config
        .fields
        .into_iter()
        .map(|(name, value)| Ok((name, proto_to_json_value(value)?)))
        .collect()
}

fn proto_to_json_value(value: Value) -> Result<serde_json::Value> {
    match value.kind {
        Some(value::Kind::NullValue(_)) => Ok(serde_json::Value::Null),
        Some(value::Kind::BoolValue(value)) => Ok(serde_json::Value::Bool(value)),
        Some(value::Kind::NumberValue(value)) => serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| miette::miette!("middleware config contains a non-finite number")),
        Some(value::Kind::StringValue(value)) => Ok(serde_json::Value::String(value)),
        Some(value::Kind::ListValue(list)) => Ok(serde_json::Value::Array(
            list.values
                .into_iter()
                .map(proto_to_json_value)
                .collect::<Result<_>>()?,
        )),
        Some(value::Kind::StructValue(object)) => Ok(serde_json::Value::Object(
            object
                .fields
                .into_iter()
                .map(|(name, value)| Ok((name, proto_to_json_value(value)?)))
                .collect::<Result<_>>()?,
        )),
        None => miette::bail!("middleware config value is missing its kind"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_policy_round_trips_canonical_yaml() {
        let source = r#"
version: 1
filesystem_policy: {}
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: ["2025-11-25"]
          strict_tool_names: false
        rules:
          - allow:
              method: tools/call
              tool: search_*
              params:
                arguments:
                  query: "public-*"
    binaries:
      - path: /usr/bin/agent
network_middlewares:
  audit:
    middleware: example/audit
    config:
      enabled: true
      nullable: null
"#;

        let policy = parse_policy_proto(source).expect("generated policy must parse");
        assert!(policy.filesystem_policy.is_some());
        assert_eq!(
            policy.network_policies["mcp"].endpoints[0]
                .mcp
                .as_ref()
                .and_then(|mcp| mcp.strict_tool_names),
            Some(false)
        );
        let yaml = serialize_policy_proto(&policy).expect("generated policy must serialize");
        let reparsed = parse_policy_proto(&yaml).expect("canonical YAML must parse");
        assert_eq!(policy, reparsed);
    }

    #[test]
    fn generated_policy_preserves_absent_and_empty_mcp_versions() {
        let absent = parse_policy_proto(
            "version: 1\nnetwork_policies:\n  mcp:\n    endpoints:\n      - { host: x, port: 443, protocol: mcp, mcp: {} }\n",
        )
        .unwrap();
        assert!(
            absent.network_policies["mcp"].endpoints[0]
                .mcp
                .as_ref()
                .unwrap()
                .versions
                .is_none()
        );

        let mut invalid = absent;
        invalid.network_policies.get_mut("mcp").unwrap().endpoints[0]
            .mcp
            .as_mut()
            .unwrap()
            .versions = Some(proto::McpVersions { values: Vec::new() });
        assert!(validate_authored_policy(&invalid).is_err());
    }

    #[test]
    fn generated_policy_rejects_runtime_authority_by_construction() {
        let fields = proto::NetworkEndpoint::default();
        let debug = format!("{fields:?}");
        assert!(!debug.contains("advisor_proposed"));
        assert!(!debug.contains("provider_credentialed"));
    }

    #[test]
    fn generated_policy_rejects_middleware_integers_that_protobuf_would_round() {
        let source = r"
version: 1
network_middlewares:
  audit:
    middleware: example/audit
    config:
      request_id: 9007199254740993
";
        let error = parse_policy_proto(source).expect_err("integer must not be rounded");
        assert!(error.to_string().contains("not representable exactly"));
    }
}
