// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor middleware registration and chain execution.

pub mod headers;
mod remote;
mod request;
mod response;
mod websocket;

pub use request::{
    HttpRequestDiagnostics, HttpRequestFinish, HttpRequestInvocation, HttpRequestInvocationOutcome,
    HttpRequestMiddlewareFailure, HttpRequestPreflightInput, HttpRequestPreflightOutcome,
    HttpRequestSession, MAX_HTTP_REQUEST_DEFERRED_BYTES, MAX_HTTP_REQUEST_STREAM_UNIT_BYTES,
};

pub use response::{
    HttpResponseDiagnostics, HttpResponseFinish, HttpResponseInvocation,
    HttpResponseInvocationOutcome, HttpResponseMiddlewareFailure, HttpResponsePreflightInput,
    HttpResponsePreflightOutcome, HttpResponseSession, MAX_HTTP_RESPONSE_RETAINED_BODY_BYTES,
    MAX_HTTP_RESPONSE_STREAM_UNIT_BYTES, is_stale_http_response_integrity_header,
};

pub use websocket::{
    WebSocketCoverage, WebSocketCoverageState, WebSocketInvocation, WebSocketInvocationOutcome,
    WebSocketMessageAdmission, WebSocketMessageOutcome, WebSocketMessageType,
    WebSocketPreflightInput, WebSocketPreflightResult, WebSocketSession,
    WebSocketSessionStartOutcome,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use miette::{Result, miette};
use prost::Message;

use openshell_core::proto::{
    Decision, Finding, HeaderMutation, HttpHeader, HttpRequestTarget, MiddlewareBinding,
    MiddlewareManifest, NetworkMiddlewareConfig, RequestContext, SandboxPolicy,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, SupervisorMiddlewareService,
    ValidateConfigRequest, ValidateConfigResponse,
};
use tokio::sync::{OnceCell, OwnedSemaphorePermit, Semaphore};
use tonic::Request;

pub use openshell_core::middleware::{
    HttpRequestResultStream, HttpResponseResultStream, InProcessMiddleware,
    SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
struct EndpointInProcessAdapter {
    endpoint: Arc<dyn SupervisorMiddlewareEndpoint>,
}

#[tonic::async_trait]
impl InProcessMiddleware for EndpointInProcessAdapter {
    async fn describe(&self) -> MiddlewareManifest {
        self.endpoint
            .describe(Request::new(()))
            .await
            .expect("in-process endpoint Describe failed")
            .into_inner()
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> Result<()> {
        let response = self
            .endpoint
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: middleware_name.to_string(),
            }))
            .await
            .map_err(|error| miette!("{error}"))?
            .into_inner();
        if response.valid {
            Ok(())
        } else {
            Err(miette!("{}", response.reason))
        }
    }

    async fn open_http_request_pre_credentials(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
    ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
        self.endpoint
            .open_http_request_pre_credentials(requests)
            .await
    }

    async fn open_websocket_session(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, tonic::Status> {
        self.endpoint.open_websocket_session(requests).await
    }

    async fn open_http_response_pre_return(
        &self,
        requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, tonic::Status> {
        self.endpoint.open_http_response_pre_return(requests).await
    }
}

/// Adapt a transport-neutral endpoint to the in-process registry contract.
///
/// Prefer implementing [`InProcessMiddleware`] directly. This compatibility
/// path preserves the request, response, and WebSocket event streams while
/// adapting configuration calls to the transport-neutral endpoint surface.
pub fn in_process_endpoint(
    endpoint: Arc<dyn SupervisorMiddlewareEndpoint>,
) -> Arc<dyn InProcessMiddleware> {
    Arc::new(EndpointInProcessAdapter { endpoint })
}

/// Maximum short-lived middleware work items allowed to wait for active
/// capacity.
///
/// Waiters do not buffer request or message bodies, so the queue can absorb a
/// larger burst without increasing the active payload-memory bound.
pub const MAX_QUEUED_MIDDLEWARE_WORK: usize = MAX_CONCURRENT_MIDDLEWARE_WORK * 2;

/// One slot in the shared middleware work budget.
///
/// Callers that buffer request or message bodies acquire this guard first and
/// retain it through evaluation, bounding aggregate buffered middleware input.
#[derive(Debug)]
pub struct MiddlewareWorkAdmission {
    _work: OwnedSemaphorePermit,
    saturated: bool,
}

impl MiddlewareWorkAdmission {
    pub fn saturated(&self) -> bool {
        self.saturated
    }
}

/// Result of attempting to enter the bounded middleware work queue.
///
/// Active-capacity saturation is ordinary backpressure: callers that obtain a
/// waiter slot eventually receive [`Self::Admitted`]. [`Self::QueueExhausted`]
/// is immediate load shedding after both active capacity and the waiter queue
/// are full.
#[derive(Debug)]
pub enum MiddlewareWorkAdmissionOutcome {
    Admitted(MiddlewareWorkAdmission),
    QueueExhausted,
}

impl MiddlewareWorkAdmissionOutcome {
    /// Preserve the existing failure behavior for protocols whose outer layer
    /// already translates middleware admission errors into a stable response
    /// or typed termination.
    pub fn into_admission(self) -> Result<MiddlewareWorkAdmission> {
        match self {
            Self::Admitted(admission) => Ok(admission),
            Self::QueueExhausted => Err(miette!(
                "middleware admission queue is full; refusing additional buffered work"
            )),
        }
    }
}

/// One slot in the shared persistent middleware session budget.
///
/// Protocol-specific session runners retain this guard while at least one
/// streaming stage remains active. Registry replacement preserves the shared
/// admission state so HTTP and WebSocket streams use the same process-wide
/// bound across registry replacement.
#[derive(Debug)]
struct MiddlewareSessionPermit {
    _session: OwnedSemaphorePermit,
}

enum MiddlewareSessionAdmission {
    Admitted(MiddlewareSessionPermit),
    AtCapacity,
}

pub use openshell_core::middleware::{
    DEFAULT_MIDDLEWARE_TIMEOUT, MAX_CONCURRENT_MIDDLEWARE_SESSIONS, MAX_CONCURRENT_MIDDLEWARE_WORK,
    MAX_MIDDLEWARE_CHAIN_FINDINGS, MAX_MIDDLEWARE_CHAIN_STAGES, MAX_MIDDLEWARE_CHAIN_TIMEOUT,
    MAX_MIDDLEWARE_CONFIGS, MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_PREFLIGHT_TIMEOUT,
    MAX_MIDDLEWARE_SELECTOR_PATTERNS, MAX_MIDDLEWARE_TIMEOUT, MIN_MIDDLEWARE_TIMEOUT,
    middleware_timeout_or_default, parse_middleware_timeout,
};

/// Largest logical payload or replacement accepted by the middleware platform.
pub const MAX_MIDDLEWARE_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
/// Largest encoded service-specific configuration attached to one evaluation.
pub const MAX_MIDDLEWARE_CONFIG_BYTES: usize = 64 * 1024;
/// Largest encoded request identity context attached to one evaluation.
pub const MAX_MIDDLEWARE_CONTEXT_BYTES: usize = 4 * 1024;
/// Largest encoded destination and request target attached to one evaluation.
pub const MAX_MIDDLEWARE_TARGET_BYTES: usize = 32 * 1024;
/// Largest number of request header lines exposed to one middleware.
pub const MAX_MIDDLEWARE_HEADERS: usize = 128;
/// Largest encoded request header collection exposed to one middleware.
pub const MAX_MIDDLEWARE_HEADER_BYTES: usize = 64 * 1024;
/// Largest operator-provided reason accepted in one middleware result.
pub const MAX_MIDDLEWARE_REASON_BYTES: usize = 4 * 1024;
/// Largest stable reason code accepted in one middleware result.
pub const MAX_MIDDLEWARE_REASON_CODE_BYTES: usize = 64;
/// Largest encoded individual finding accepted from one middleware stage.
pub const MAX_MIDDLEWARE_FINDING_BYTES: usize = 4 * 1024;
/// Largest number of metadata entries accepted from one middleware stage.
pub const MAX_MIDDLEWARE_METADATA_ENTRIES: usize = 64;
/// Largest combined metadata key/value payload accepted from one middleware stage.
pub const MAX_MIDDLEWARE_METADATA_BYTES: usize = 32 * 1024;

const MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES: usize = 64 * 1024;
const MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES: usize = 64 * 1024;
const MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES: usize = MAX_MIDDLEWARE_CONFIG_BYTES
    + MAX_MIDDLEWARE_CONTEXT_BYTES
    + MAX_MIDDLEWARE_TARGET_BYTES
    + MAX_MIDDLEWARE_HEADER_BYTES
    + MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES;
const MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES: usize = MAX_MIDDLEWARE_REASON_BYTES
    + MAX_MIDDLEWARE_REASON_CODE_BYTES
    + MAX_MIDDLEWARE_HEADER_MUTATION_WIRE_BYTES
    + MAX_MIDDLEWARE_FINDINGS_PER_STAGE * MAX_MIDDLEWARE_FINDING_BYTES
    + MAX_MIDDLEWARE_METADATA_BYTES
    + MAX_MIDDLEWARE_PROTOBUF_OVERHEAD_BYTES;
/// gRPC envelope headroom derived from every bounded non-payload component.
pub const MIDDLEWARE_GRPC_ENVELOPE_BYTES: usize =
    if MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES > MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES {
        MAX_MIDDLEWARE_REQUEST_ENVELOPE_BYTES
    } else {
        MAX_MIDDLEWARE_RESPONSE_ENVELOPE_BYTES
    };
/// gRPC message limit derived from the payload and bounded protobuf components.
pub const MIDDLEWARE_GRPC_MESSAGE_BYTES: usize =
    MAX_MIDDLEWARE_PAYLOAD_BYTES + MIDDLEWARE_GRPC_ENVELOPE_BYTES;

const MAX_STABLE_IDENTIFIER_BYTES: usize = 128;
const EXTERNAL_FINDING_LABEL: &str = "External middleware finding";
#[cfg(test)]
const HTTP_REQUEST_OPERATION: SupervisorMiddlewareOperation =
    SupervisorMiddlewareOperation::HttpRequest;
#[cfg(test)]
const PRE_CREDENTIALS_PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    FailClosed,
    FailOpen,
}

impl OnError {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "fail_closed" => Ok(Self::FailClosed),
            "fail_open" => Ok(Self::FailOpen),
            other => Err(miette!(
                "invalid middleware on_error '{other}', expected fail_closed or fail_open"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub implementation: String,
    pub order: i32,
    pub config: prost_types::Struct,
    pub on_error: OnError,
}

impl TryFrom<(&str, &NetworkMiddlewareConfig)> for ChainEntry {
    type Error = miette::Report;

    fn try_from((name, value): (&str, &NetworkMiddlewareConfig)) -> Result<Self> {
        if name.is_empty() {
            return Err(miette!("middleware config name cannot be empty"));
        }
        if value.middleware.is_empty() {
            return Err(miette!(
                "middleware config '{}' must reference a middleware",
                name
            ));
        }
        Ok(Self {
            name: name.to_string(),
            implementation: value.middleware.clone(),
            order: value.order,
            config: value.config.clone().unwrap_or_default(),
            on_error: OnError::parse(&value.on_error)?,
        })
    }
}

/// A policy-selected middleware config joined with metadata reported by its
/// service's `Describe` call.
///
/// An unregistered implementation is retained so `on_error` can decide whether
/// the request fails open or closed. A registered implementation without the
/// requested binding is not part of this chain.
#[derive(Clone)]
pub struct DescribedChainEntry {
    entry: ChainEntry,
    service: Option<Arc<MiddlewareServiceState>>,
    binding: Option<MiddlewareBinding>,
    max_payload_bytes: usize,
    timeout: Duration,
}

struct DescribedChain {
    entries: Vec<DescribedChainEntry>,
    unbound: Vec<ChainEntry>,
}

impl DescribedChainEntry {
    pub fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    pub fn on_error(&self) -> OnError {
        self.entry.on_error
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// True when this entry resolved to a registered binding and will be
    /// evaluated. When false, the binding is absent from the current registry
    /// and the entry is handled entirely by its `on_error` policy, so it
    /// imposes no payload-buffering limit on the chain.
    pub fn is_resolved(&self) -> bool {
        self.binding.is_some()
    }
}

/// Re-checks a middleware-transformed request body against sandbox policy.
///
/// Returns `Some(reason)` to deny the chain, `None` to proceed. Invoked after
/// each stage that replaces the body so neither a later stage nor the upstream
/// sees a payload the policy would reject. Protocols with no body-aware policy
/// select [`TransformedBodyPolicy::NotPolicyRelevant`] instead.
pub type TransformedBodyValidator<'a> = dyn Fn(&[u8]) -> Result<Option<String>> + Send + Sync + 'a;

/// Whether middleware body replacements affect the selected request policy.
///
/// The network pipeline must choose a mode explicitly. This avoids representing
/// a security-relevant re-evaluation requirement as an optional callback where
/// an omitted value is indistinguishable from an intentionally body-independent
/// protocol.
#[derive(Clone, Copy)]
pub enum TransformedBodyPolicy<'a> {
    /// The selected policy does not inspect the request body.
    NotPolicyRelevant,
    /// Re-evaluate every body replacement before the next stage runs.
    Reevaluate(&'a TransformedBodyValidator<'a>),
}

#[derive(Debug, Clone)]
pub struct HttpRequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub query: String,
    /// Lowercased request headers in wire order. Repeated header names are
    /// preserved as separate entries so middleware inspects every value the
    /// upstream will receive.
    pub headers: Vec<(String, String)>,
    /// Lowercased names nominated by the original request's `Connection`
    /// headers. Their values are not exposed to middleware, but mutations must
    /// still treat these dynamically hop-by-hop fields as protected.
    pub connection_nominated_headers: Vec<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChainOutcome {
    pub allowed: bool,
    pub reason: String,
    pub body: Vec<u8>,
    /// Ordered, validated mutations to replay against the original raw request.
    pub header_mutations: Vec<HeaderMutation>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub applied: Vec<MiddlewareInvocation>,
    /// Present only when a middleware completed successfully and explicitly
    /// denied the request. Fail-closed service errors and transformed-body
    /// policy denials are not represented as middleware decisions.
    pub denial: Option<MiddlewareDenial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareDenial {
    /// Stable policy-local middleware config identity.
    pub config_name: String,
    /// Validated service-defined code. Free-form service reason text is never
    /// carried into client responses or security logs.
    pub reason_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedFinding {
    pub middleware: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareInvocation {
    pub name: String,
    pub implementation: String,
    pub decision: Decision,
    pub transformed: bool,
    /// True when the middleware could not be evaluated and `on_error` was applied
    /// (service error, malformed/unsafe response, etc.). The `decision` reflects
    /// the `on_error` outcome, not a decision the middleware actually returned.
    pub failed: bool,
}

#[derive(Clone)]
pub struct ChainRunner {
    registry: Arc<MiddlewareRegistry>,
}

#[derive(Clone)]
enum MiddlewareDispatch {
    /// Built-ins borrow the current request state and never construct protobuf.
    InProcess(Arc<dyn InProcessMiddleware>),
    /// Operator services receive an owned protobuf through the gRPC adapter.
    Grpc(remote::GrpcMiddlewareService),
}

impl MiddlewareDispatch {
    async fn describe(
        &self,
    ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
        match self {
            Self::InProcess(service) => Ok(tonic::Response::new(service.describe().await)),
            Self::Grpc(service) => service.describe().await,
        }
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
        match self {
            Self::InProcess(service) => Ok(tonic::Response::new(
                match service.validate_config(middleware_name, config).await {
                    Ok(()) => ValidateConfigResponse {
                        valid: true,
                        reason: String::new(),
                    },
                    Err(error) => ValidateConfigResponse {
                        valid: false,
                        reason: error.to_string(),
                    },
                },
            )),
            Self::Grpc(service) => service.validate_config(middleware_name, config).await,
        }
    }

    async fn open_http_request_pre_credentials(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
    ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_http_request_pre_credentials(receiver).await,
            Self::Grpc(service) => service.open_http_request_pre_credentials(receiver).await,
        }
    }

    async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_websocket_session(receiver).await,
            Self::Grpc(service) => service.open_websocket_session(receiver).await,
        }
    }

    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, tonic::Status> {
        match self {
            Self::InProcess(service) => service.open_http_response_pre_return(receiver).await,
            Self::Grpc(service) => service.open_http_response_pre_return(receiver).await,
        }
    }
}

struct MiddlewareServiceState {
    /// Policy-facing built-in name or operator-owned registration name. The
    /// single-service test constructor leaves this empty and uses the manifest
    /// name after Describe.
    attachment_name: Option<String>,
    service: MiddlewareDispatch,
    manifest: OnceCell<MiddlewareManifest>,
    diagnostic_policy: MiddlewareDiagnosticPolicy,
    operator_max_payload_bytes: Option<usize>,
    operator_timeout: Duration,
}

impl MiddlewareServiceState {
    fn timeout_for_binding(&self, binding: &MiddlewareBinding) -> Result<Duration> {
        if binding.request_timeout.is_none() {
            Ok(self.operator_timeout)
        } else {
            middleware_proto_timeout_or_default(binding.request_timeout.as_ref())
                .map(|binding_timeout| binding_timeout.min(self.operator_timeout))
                .map_err(|reason| miette!("middleware binding has invalid timeout: {reason}"))
        }
    }
}

async fn call_with_timeout<T>(
    timeout: Duration,
    operation: &'static str,
    future: impl Future<Output = std::result::Result<tonic::Response<T>, tonic::Status>>,
) -> std::result::Result<tonic::Response<T>, tonic::Status> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        tonic::Status::deadline_exceeded(format!("middleware {operation} timed out"))
    })?
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MiddlewareDiagnosticPolicy {
    Preserve,
    Normalize,
}

impl MiddlewareDiagnosticPolicy {
    fn error_reason(self, error: &tonic::Status) -> String {
        match self {
            Self::Preserve => safe_reason(&error.to_string()),
            Self::Normalize => "external_service_error".to_string(),
        }
    }

    fn header_mutation_error_reason(self, error: &headers::HeaderMutationError) -> String {
        match self {
            Self::Preserve => safe_reason(&error.to_string()),
            Self::Normalize => error.code().to_string(),
        }
    }
}

/// Validated middleware services available to a gateway or one supervisor.
///
/// In-process services are supplied by the composition root; the generic
/// registry does not select concrete built-ins. All in-process and remote
/// services are described before construction succeeds, so callers never
/// observe a partially registered service set.
#[derive(Clone)]
pub struct MiddlewareRegistry {
    services: Arc<Vec<Arc<MiddlewareServiceState>>>,
    registered_services: Arc<Vec<RegisteredMiddlewareService>>,
    middleware_names: Arc<HashSet<String>>,
    work_admission: Arc<Semaphore>,
    work_admission_waiters: Arc<Semaphore>,
    session_admission: Arc<Semaphore>,
}

impl std::fmt::Debug for MiddlewareRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MiddlewareRegistry")
            .field("service_count", &self.services.len())
            .field("registered_service_count", &self.registered_services.len())
            .field("middleware_count", &self.middleware_names.len())
            .field(
                "available_work_permits",
                &self.work_admission.available_permits(),
            )
            .field(
                "available_session_permits",
                &self.session_admission.available_permits(),
            )
            .finish()
    }
}

#[derive(Clone)]
struct RegisteredMiddlewareService {
    registration: SupervisorMiddlewareService,
}

impl Default for MiddlewareRegistry {
    fn default() -> Self {
        Self {
            services: Arc::new(Vec::new()),
            registered_services: Arc::new(Vec::new()),
            middleware_names: Arc::new(HashSet::new()),
            work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
            work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
            session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
        }
    }
}

/// Validate one external middleware registration without opening its transport.
pub fn validate_registration_config(registration: &SupervisorMiddlewareService) -> Result<()> {
    validate_registration(registration).map(|_| ())
}

fn validate_registration(registration: &SupervisorMiddlewareService) -> Result<Duration> {
    if !is_stable_identifier(&registration.name) {
        return Err(miette!(
            "supervisor middleware registration names must be 1-{MAX_STABLE_IDENTIFIER_BYTES} bytes and contain only ASCII letters, digits, '.', '_', '-', or '/'"
        ));
    }
    if registration.name.starts_with("openshell/") {
        return Err(miette!(
            "middleware registration '{}' cannot claim the reserved openshell/ namespace",
            registration.name
        ));
    }
    if !registration.grpc_endpoint.starts_with("http://")
        && !registration.grpc_endpoint.starts_with("https://")
    {
        return Err(miette!(
            "middleware registration '{}' grpc_endpoint must use http:// or https://",
            registration.name
        ));
    }
    if registration.max_payload_bytes > MAX_MIDDLEWARE_PAYLOAD_BYTES as u64 {
        return Err(miette!(
            "middleware registration '{}' max_payload_bytes exceeds the platform maximum of {MAX_MIDDLEWARE_PAYLOAD_BYTES}",
            registration.name
        ));
    }
    middleware_proto_timeout_or_default(registration.request_timeout.as_ref()).map_err(|reason| {
        miette!(
            "middleware registration '{}' has invalid timeout: {reason}",
            registration.name
        )
    })
}

fn is_stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STABLE_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}

fn is_stable_reason_code(value: &str) -> bool {
    value.len() <= MAX_MIDDLEWARE_REASON_CODE_BYTES
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn middleware_denial_reason(config_name: &str, reason_code: Option<&str>) -> String {
    let config_id: String = config_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(MAX_STABLE_IDENTIFIER_BYTES)
        .collect();
    reason_code.map_or_else(
        || format!("middleware_denied:{config_id}"),
        |code| format!("middleware_denied:{config_id}:{code}"),
    )
}

fn validate_payload_limit(source: &str, binding: &MiddlewareBinding) -> Result<usize> {
    if binding.max_payload_bytes == 0 {
        return Err(miette!("{source} must advertise a non-zero payload limit"));
    }
    if binding.max_payload_bytes > MAX_MIDDLEWARE_PAYLOAD_BYTES as u64 {
        return Err(miette!(
            "{source} payload limit exceeds the platform maximum of {MAX_MIDDLEWARE_PAYLOAD_BYTES}"
        ));
    }
    usize::try_from(binding.max_payload_bytes)
        .map_err(|_| miette!("{source} reports a payload limit too large for this platform"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedBinding {
    HttpPreCredentials,
    HttpPostCredentials,
    HttpResponsePreReturn,
    WebSocketPreCredentials,
}

fn supported_binding(source: &str, binding: &MiddlewareBinding) -> Result<SupportedBinding> {
    match (
        SupervisorMiddlewareOperation::try_from(binding.operation).ok(),
        SupervisorMiddlewarePhase::try_from(binding.phase).ok(),
    ) {
        (
            Some(SupervisorMiddlewareOperation::HttpRequest),
            Some(SupervisorMiddlewarePhase::PreCredentials),
        ) => Ok(SupportedBinding::HttpPreCredentials),
        (
            Some(SupervisorMiddlewareOperation::HttpRequest),
            Some(SupervisorMiddlewarePhase::PostCredentials),
        ) => Ok(SupportedBinding::HttpPostCredentials),
        (
            Some(SupervisorMiddlewareOperation::HttpResponse),
            Some(SupervisorMiddlewarePhase::PreReturn),
        ) => Ok(SupportedBinding::HttpResponsePreReturn),
        (
            Some(SupervisorMiddlewareOperation::WebsocketMessage),
            Some(SupervisorMiddlewarePhase::PreCredentials),
        ) => Ok(SupportedBinding::WebSocketPreCredentials),
        (
            Some(SupervisorMiddlewareOperation::WebsocketMessage),
            Some(SupervisorMiddlewarePhase::PreReturn),
        ) => Err(miette!(
            "{source} advertises WEBSOCKET_MESSAGE/PRE_RETURN, which is not yet supported"
        )),
        _ => Err(miette!(
            "{source} advertises an unsupported middleware operation/phase pair"
        )),
    }
}

fn validate_manifest_bindings(
    source: &str,
    manifest: &MiddlewareManifest,
    operator_max_payload_bytes: Option<usize>,
) -> Result<()> {
    if manifest.bindings.is_empty() {
        return Err(miette!("{source} describes no bindings"));
    }

    let mut described_pairs = HashSet::with_capacity(manifest.bindings.len());
    for binding in &manifest.bindings {
        supported_binding(source, binding)?;
        if !described_pairs.insert((binding.operation, binding.phase)) {
            return Err(miette!(
                "{source} describes a duplicate middleware operation/phase pair"
            ));
        }
        let advertised = validate_payload_limit(source, binding)?;
        if binding.request_timeout.is_some() {
            middleware_proto_timeout_or_default(binding.request_timeout.as_ref())
                .map_err(|reason| miette!("{source} has invalid timeout for binding: {reason}"))?;
        }
        if operator_max_payload_bytes.is_some_and(|limit| limit > advertised) {
            return Err(miette!(
                "{source} max_payload_bytes ({}) exceeds the binding capability ({advertised})",
                operator_max_payload_bytes.expect("operator limit checked above")
            ));
        }
        if operator_max_payload_bytes == Some(0) {
            return Err(miette!(
                "{source} must configure max_payload_bytes for every payload-bearing binding"
            ));
        }
    }
    Ok(())
}

fn middleware_proto_timeout_or_default(
    value: Option<&prost_types::Duration>,
) -> std::result::Result<Duration, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_MIDDLEWARE_TIMEOUT);
    };
    let timeout =
        openshell_core::time::duration_to_std(value).map_err(|error| error.to_string())?;
    if !(MIN_MIDDLEWARE_TIMEOUT..=MAX_MIDDLEWARE_TIMEOUT).contains(&timeout) {
        return Err(format!(
            "must be between {}ms and {}s",
            MIN_MIDDLEWARE_TIMEOUT.as_millis(),
            MAX_MIDDLEWARE_TIMEOUT.as_secs()
        ));
    }
    Ok(timeout)
}

fn validate_external_manifest(
    registration: &SupervisorMiddlewareService,
    manifest: &MiddlewareManifest,
    operator_max_payload_bytes: usize,
    authenticated: bool,
) -> Result<()> {
    if manifest.bindings.iter().any(|binding| {
        SupervisorMiddlewarePhase::try_from(binding.phase)
            .is_ok_and(|phase| phase == SupervisorMiddlewarePhase::PostCredentials)
    }) {
        return Err(miette!(
            "external middleware registration '{}' advertises POST_CREDENTIALS, which is reserved for trusted in-process built-ins",
            registration.name
        ));
    }
    validate_manifest_bindings(
        &format!("external middleware registration '{}'", registration.name),
        manifest,
        Some(operator_max_payload_bytes),
    )?;
    validate_expected_audience(
        &registration.name,
        &registration.audience,
        &manifest.expected_audience,
        authenticated && !registration.allow_insecure_transport,
    )
}

/// After authenticated Describe succeeds, reject a registration whose
/// configured audience differs from the one the service says it verifies.
///
/// This is a post-authentication consistency assertion, not audience discovery:
/// a strict verifier may reject an incorrect audience before returning its
/// manifest. A service that does not advertise an audience is accepted unchanged.
fn validate_expected_audience(
    registration_name: &str,
    configured: &str,
    advertised: &str,
    authenticated: bool,
) -> Result<()> {
    if !authenticated || advertised.is_empty() {
        return Ok(());
    }
    if advertised != configured {
        return Err(miette!(
            "middleware registration '{registration_name}' expects audience \
             '{advertised}' but OpenShell is configured to mint '{configured}'"
        ));
    }
    Ok(())
}

impl MiddlewareRegistry {
    /// Describe in-process services, then connect and validate every
    /// operator-provided service registration.
    pub async fn connect_services(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
    ) -> Result<Self> {
        Self::connect_services_inner(in_process_services, registrations, None).await
    }

    /// Connect services with optional refreshable credentials keyed by
    /// operator registration name. A configured credential is shared by all
    /// generated client clones and can rotate without rebuilding the registry.
    pub async fn connect_services_authenticated(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
        credentials: &HashMap<String, openshell_extension_core::BearerTokenSlot>,
    ) -> Result<Self> {
        Self::connect_services_inner(in_process_services, registrations, Some(credentials)).await
    }

    async fn connect_services_inner(
        in_process_services: Vec<Arc<dyn InProcessMiddleware>>,
        registrations: Vec<SupervisorMiddlewareService>,
        credentials: Option<&HashMap<String, openshell_extension_core::BearerTokenSlot>>,
    ) -> Result<Self> {
        let mut services = Vec::with_capacity(in_process_services.len() + registrations.len());
        let mut registered_services = Vec::with_capacity(registrations.len());
        let mut middleware_names = HashSet::new();

        for service in in_process_services {
            let service = MiddlewareDispatch::InProcess(service);
            let manifest =
                call_with_timeout(DEFAULT_MIDDLEWARE_TIMEOUT, "Describe", service.describe())
                    .await
                    .map(tonic::Response::into_inner)
                    .map_err(|error| {
                        miette!(
                            "in-process middleware Describe failed: {}",
                            safe_reason(&error.to_string())
                        )
                    })?;
            let source = if manifest.name.trim().is_empty() {
                "in-process middleware service".to_string()
            } else {
                format!("in-process middleware service '{}'", manifest.name)
            };
            if !is_stable_identifier(&manifest.name) {
                return Err(miette!(
                    "in-process middleware names must be 1-{MAX_STABLE_IDENTIFIER_BYTES} bytes and contain only ASCII letters, digits, '.', '_', '-', or '/'"
                ));
            }
            if !middleware_names.insert(manifest.name.clone()) {
                return Err(miette!(
                    "duplicate supervisor middleware name '{}'",
                    manifest.name
                ));
            }
            validate_manifest_bindings(&source, &manifest, None)?;
            let attachment_name = manifest.name.clone();
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                attachment_name: Some(attachment_name),
                service,
                manifest: manifest_cell,
                diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                operator_max_payload_bytes: None,
                operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
            }));
        }

        for registration in registrations {
            let operator_timeout = validate_registration(&registration)?;
            if !middleware_names.insert(registration.name.clone()) {
                return Err(miette!(
                    "duplicate supervisor middleware registration name '{}'",
                    registration.name
                ));
            }

            let operator_max_payload_bytes = usize::try_from(registration.max_payload_bytes)
                .map_err(|_| {
                    miette!(
                        "middleware registration '{}' payload limit is too large for this platform",
                        registration.name
                    )
                })?;
            // A registration the operator opted out of extension
            // authentication carries no credential by design. Every other
            // registration must have one, or the connection fails closed
            // rather than silently downgrading to an unauthenticated call.
            let bearer = credentials
                .filter(|_| !registration.allow_insecure_transport)
                .map(|credentials| {
                    credentials.get(&registration.name).cloned().ok_or_else(|| {
                        miette!(
                            "middleware registration '{}' is missing its extension credential",
                            registration.name
                        )
                    })
                })
                .transpose()?;
            let authenticated = bearer.is_some();
            let service = MiddlewareDispatch::Grpc(
                remote::GrpcMiddlewareService::connect(
                    &registration.name,
                    &registration.grpc_endpoint,
                    &registration.tls_ca_cert_pem,
                    bearer,
                )
                .await?,
            );
            let manifest = call_with_timeout(operator_timeout, "Describe", service.describe())
                .await
                .map(tonic::Response::into_inner)
                .map_err(|error| {
                    miette!(
                        "middleware registration '{}' Describe failed: {}",
                        registration.name,
                        safe_reason(&error.to_string())
                    )
                })?;
            validate_external_manifest(
                &registration,
                &manifest,
                operator_max_payload_bytes,
                authenticated,
            )?;
            let manifest_cell = OnceCell::new();
            manifest_cell
                .set(manifest)
                .map_err(|_| miette!("middleware manifest cache initialized twice"))?;
            services.push(Arc::new(MiddlewareServiceState {
                attachment_name: Some(registration.name.clone()),
                service,
                manifest: manifest_cell,
                diagnostic_policy: MiddlewareDiagnosticPolicy::Normalize,
                operator_max_payload_bytes: Some(operator_max_payload_bytes),
                operator_timeout,
            }));
            registered_services.push(RegisteredMiddlewareService { registration });
        }

        Ok(Self {
            services: Arc::new(services),
            registered_services: Arc::new(registered_services),
            middleware_names: Arc::new(middleware_names),
            work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
            work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
            session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
        })
    }

    /// Validate implementation-owned configuration for every middleware entry.
    pub async fn validate_policy_configs(&self, policy: &SandboxPolicy) -> Result<()> {
        ensure_config_capacity(policy.network_middlewares.len())?;
        let runner = ChainRunner::from_registry(self.clone());
        for (name, config) in &policy.network_middlewares {
            runner
                .validate_config(
                    &config.middleware,
                    config.config.clone().unwrap_or_default(),
                )
                .await
                .map_err(|error| {
                    miette!(
                        "middleware config '{}' is invalid: {}",
                        name,
                        safe_reason(&error.to_string())
                    )
                })?;
        }
        Ok(())
    }

    /// Check that every policy attachment still belongs to the current static
    /// registry without making a network call.
    pub fn ensure_policy_middlewares_registered(&self, policy: &SandboxPolicy) -> Result<()> {
        for (name, config) in &policy.network_middlewares {
            if !self.middleware_names.contains(&config.middleware) {
                return Err(miette!(
                    "middleware '{}' used by config '{}' is not registered",
                    config.middleware,
                    name
                ));
            }
        }
        Ok(())
    }

    /// Return only operator-registered services referenced by the effective policy.
    pub fn required_services(
        &self,
        policy: Option<&SandboxPolicy>,
    ) -> Vec<SupervisorMiddlewareService> {
        let Some(policy) = policy else {
            return Vec::new();
        };
        let selected: HashSet<&str> = policy
            .network_middlewares
            .values()
            .map(|config| config.middleware.as_str())
            .collect();
        self.registered_services
            .iter()
            .filter(|service| selected.contains(service.registration.name.as_str()))
            .map(|service| service.registration.clone())
            .collect()
    }
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self::from_registry(MiddlewareRegistry::default())
    }
}

impl ChainRunner {
    /// Construct a runner around one in-process middleware implementation.
    #[must_use]
    pub fn new(service: Arc<dyn InProcessMiddleware>) -> Self {
        Self::from_service(MiddlewareDispatch::InProcess(service))
    }

    /// Construct a runner around a legacy transport-neutral in-process endpoint.
    #[must_use]
    pub fn from_endpoint(endpoint: Arc<dyn SupervisorMiddlewareEndpoint>) -> Self {
        Self::new(in_process_endpoint(endpoint))
    }

    fn from_service(service: MiddlewareDispatch) -> Self {
        Self {
            registry: Arc::new(MiddlewareRegistry {
                services: Arc::new(vec![Arc::new(MiddlewareServiceState {
                    attachment_name: None,
                    service,
                    manifest: OnceCell::new(),
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                    operator_max_payload_bytes: None,
                    operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                })]),
                registered_services: Arc::new(Vec::new()),
                middleware_names: Arc::new(HashSet::new()),
                work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
                work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
                session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
            }),
        }
    }

    #[cfg(test)]
    fn new_protobuf_for_tests(endpoint: Arc<dyn SupervisorMiddlewareEndpoint>) -> Self {
        Self::from_service(MiddlewareDispatch::Grpc(
            remote::GrpcMiddlewareService::from_service(endpoint),
        ))
    }

    pub fn from_registry(registry: MiddlewareRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
        }
    }

    /// Build a runner for a replacement registry while preserving process-wide
    /// admission budgets across registry generations.
    #[must_use]
    pub fn with_replacement_registry(&self, mut registry: MiddlewareRegistry) -> Self {
        registry.work_admission = Arc::clone(&self.registry.work_admission);
        registry.work_admission_waiters = Arc::clone(&self.registry.work_admission_waiters);
        registry.session_admission = Arc::clone(&self.registry.session_admission);
        Self::from_registry(registry)
    }

    /// Reserve one unit of short-lived middleware work.
    ///
    /// The bounded waiter queue provides backpressure for work expected to
    /// complete promptly, such as HTTP evaluations, WebSocket messages, and
    /// streaming-session preflight.
    pub async fn reserve_middleware_work(&self) -> Result<MiddlewareWorkAdmissionOutcome> {
        if let Ok(permit) = Arc::clone(&self.registry.work_admission).try_acquire_owned() {
            Ok(MiddlewareWorkAdmissionOutcome::Admitted(
                MiddlewareWorkAdmission {
                    _work: permit,
                    saturated: false,
                },
            ))
        } else {
            let Ok(waiter) = Arc::clone(&self.registry.work_admission_waiters).try_acquire_owned()
            else {
                return Ok(MiddlewareWorkAdmissionOutcome::QueueExhausted);
            };
            let permit = Arc::clone(&self.registry.work_admission)
                .acquire_owned()
                .await
                .map_err(|_| miette!("middleware admission semaphore closed"))?;
            drop(waiter);
            Ok(MiddlewareWorkAdmissionOutcome::Admitted(
                MiddlewareWorkAdmission {
                    _work: permit,
                    saturated: true,
                },
            ))
        }
    }

    /// Reserve middleware work for a caller whose established external
    /// behavior treats queue exhaustion as a middleware processing failure.
    pub async fn reserve_middleware_work_admission(&self) -> Result<MiddlewareWorkAdmission> {
        self.reserve_middleware_work().await?.into_admission()
    }

    /// Attempt to reserve one persistent middleware session without waiting.
    ///
    /// Long-lived sessions have no useful queueing bound because their release
    /// time is unrelated to middleware latency. Protocol-specific runners apply
    /// their own `on_error` semantics when the shared session budget is full.
    fn try_reserve_middleware_session(&self) -> MiddlewareSessionAdmission {
        Arc::clone(&self.registry.session_admission)
            .try_acquire_owned()
            .map_or(MiddlewareSessionAdmission::AtCapacity, |permit| {
                MiddlewareSessionAdmission::Admitted(MiddlewareSessionPermit { _session: permit })
            })
    }

    async fn manifests(&self) -> Result<Vec<(Arc<MiddlewareServiceState>, MiddlewareManifest)>> {
        let mut manifests = Vec::with_capacity(self.registry.services.len());
        for state in self.registry.services.iter() {
            let manifest = state
                .manifest
                .get_or_try_init(|| async {
                    call_with_timeout(state.operator_timeout, "Describe", state.service.describe())
                        .await
                        .map(tonic::Response::into_inner)
                        .map_err(|error| {
                            miette!(
                                "middleware Describe failed: {}",
                                safe_reason(&error.to_string())
                            )
                        })
                })
                .await?;
            manifests.push((Arc::clone(state), manifest.clone()));
        }
        Ok(manifests)
    }

    fn attachment_name<'a>(
        state: &'a MiddlewareServiceState,
        manifest: &'a MiddlewareManifest,
    ) -> &'a str {
        state
            .attachment_name
            .as_deref()
            .unwrap_or(manifest.name.as_str())
    }

    fn binding(
        manifest: &MiddlewareManifest,
        operation: SupervisorMiddlewareOperation,
        phase: SupervisorMiddlewarePhase,
    ) -> Option<&MiddlewareBinding> {
        manifest
            .bindings
            .iter()
            .find(|binding| binding.operation == operation as i32 && binding.phase == phase as i32)
    }

    pub async fn describe_chain(&self, entries: &[ChainEntry]) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::HttpRequest,
                SupervisorMiddlewarePhase::PreCredentials,
            )
            .await?
            .entries)
    }

    pub async fn describe_websocket_chain(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::WebsocketMessage,
                SupervisorMiddlewarePhase::PreCredentials,
            )
            .await?
            .entries)
    }

    pub async fn describe_http_response_chain(
        &self,
        entries: &[ChainEntry],
    ) -> Result<Vec<DescribedChainEntry>> {
        Ok(self
            .describe_chain_for(
                entries,
                SupervisorMiddlewareOperation::HttpResponse,
                SupervisorMiddlewarePhase::PreReturn,
            )
            .await?
            .entries)
    }

    async fn describe_chain_for(
        &self,
        entries: &[ChainEntry],
        operation: SupervisorMiddlewareOperation,
        phase: SupervisorMiddlewarePhase,
    ) -> Result<DescribedChain> {
        ensure_chain_capacity(entries.len())?;
        let manifests = self.manifests().await?;
        let mut entries = entries.to_vec();
        sort_chain_entries(&mut entries);
        let mut described_entries = Vec::with_capacity(entries.len());
        let mut unbound = Vec::new();
        for entry in entries {
            let Some((state, manifest)) = manifests.iter().find(|(state, manifest)| {
                Self::attachment_name(state, manifest) == entry.implementation
            }) else {
                described_entries.push(DescribedChainEntry {
                    entry,
                    service: None,
                    binding: None,
                    max_payload_bytes: 0,
                    timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                });
                continue;
            };
            let Some(binding) = Self::binding(manifest, operation, phase).copied() else {
                // The config remains globally ordered, but it does not
                // participate in this exact operation/phase chain.
                unbound.push(entry);
                continue;
            };
            let timeout = state.timeout_for_binding(&binding)?;
            let advertised = validate_payload_limit("middleware manifest", &binding)?;
            let max_payload_bytes = state.operator_max_payload_bytes.unwrap_or(advertised);
            described_entries.push(DescribedChainEntry {
                entry,
                service: Some(Arc::clone(state)),
                binding: Some(binding),
                max_payload_bytes,
                timeout,
            });
        }
        ensure_chain_capacity(described_entries.len())?;
        Ok(DescribedChain {
            entries: described_entries,
            unbound,
        })
    }

    pub async fn validate_config(
        &self,
        middleware_name: &str,
        config: prost_types::Struct,
    ) -> Result<()> {
        if config.encoded_len() > MAX_MIDDLEWARE_CONFIG_BYTES {
            return Err(miette!(
                "middleware config exceeds the platform maximum of {MAX_MIDDLEWARE_CONFIG_BYTES} encoded bytes"
            ));
        }
        let manifests = self.manifests().await?;
        let Some((state, _manifest)) = manifests
            .iter()
            .find(|(state, manifest)| Self::attachment_name(state, manifest) == middleware_name)
        else {
            return Err(miette!("middleware '{middleware_name}' is not registered"));
        };
        let response = call_with_timeout(
            state.operator_timeout,
            "ValidateConfig",
            state.service.validate_config(middleware_name, &config),
        )
        .await
        .map(tonic::Response::into_inner)
        .map_err(|error| {
            miette!(
                "middleware ValidateConfig failed: {}",
                safe_reason(&error.to_string())
            )
        })?;
        if response.valid {
            Ok(())
        } else {
            Err(miette!("{}", safe_reason(&response.reason)))
        }
    }

    pub async fn evaluate(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        let entries = self.describe_chain(entries).await?;
        self.evaluate_described(&entries, input).await
    }

    pub async fn evaluate_described(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        self.evaluate_described_with_policy(
            entries,
            input,
            TransformedBodyPolicy::NotPolicyRelevant,
        )
        .await
    }

    /// Evaluate a described chain, re-checking the request body against sandbox
    /// policy after every stage that replaces it. Policy runs on the original
    /// body before the chain, so without this a stage could hand the next stage
    /// (or the upstream) a payload the policy rejects. When the evaluator returns
    /// a deny reason the chain stops with that reason, so no later stage ever
    /// sees a non-compliant body. Body-independent protocols must select
    /// [`TransformedBodyPolicy::NotPolicyRelevant`] explicitly.
    pub async fn evaluate_described_with_policy(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
        transformed_body_policy: TransformedBodyPolicy<'_>,
    ) -> Result<ChainOutcome> {
        let admission = if entries.is_empty() {
            None
        } else {
            Some(self.reserve_middleware_work_admission().await?)
        };
        self.evaluate_described_with_policy_admitted(
            entries,
            input,
            transformed_body_policy,
            admission,
        )
        .await
    }

    /// Evaluate a chain using capacity reserved before its request body was
    /// buffered. The guard is retained until the ordered chain completes.
    pub async fn evaluate_described_with_policy_admitted(
        &self,
        entries: &[DescribedChainEntry],
        input: HttpRequestInput,
        transformed_body_policy: TransformedBodyPolicy<'_>,
        admission: Option<MiddlewareWorkAdmission>,
    ) -> Result<ChainOutcome> {
        ensure_chain_capacity(entries.len())?;
        let HttpRequestInput {
            request_id,
            sandbox_id,
            sandbox_name,
            workspace,
            scheme,
            host,
            port,
            method,
            path,
            query,
            headers,
            connection_nominated_headers,
            body,
        } = input;
        let context = RequestContext {
            request_id,
            sandbox_id,
            sandbox_name,
            workspace,
            originating_process: None,
        };
        let target = HttpRequestTarget {
            scheme,
            host,
            port: u32::from(port),
            method,
            path,
            query,
        };
        let mut headers = headers
            .into_iter()
            .map(|(name, value)| HttpHeader { name, value })
            .collect::<Vec<_>>();
        let mut body = body;
        let mut header_mutations = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();
        // The request session budget now bounds the streaming lifecycle, so a
        // compatibility caller's pre-buffer admission can be released before
        // opening the stage stream.
        drop(admission);

        // The compatibility collector evaluates one stage at a time so
        // body-aware protocols can re-run policy after every accepted
        // replacement. The HTTP relay uses the streaming session API directly
        // and does not collect a complete request in memory.
        for entry in entries {
            let preflight = self
                .preflight_described_http_request_with_owned(
                    vec![entry.clone()],
                    HttpRequestPreflightInput {
                        context: context.clone(),
                        target: target.clone(),
                        declared_body_length: Some(body.len() as u64),
                        headers: headers.clone(),
                        connection_nominated_headers: connection_nominated_headers.clone(),
                    },
                    false,
                )
                .await?;

            findings.extend(preflight.findings.clone());
            metadata.extend(preflight.metadata.clone());
            let mut stage_failed = preflight.invocations.iter().any(|item| item.failed);
            let headers_transformed = preflight.headers != headers;
            headers = preflight.headers;
            header_mutations.extend(preflight.header_mutations);

            if !preflight.allowed {
                applied.push(MiddlewareInvocation {
                    name: entry.entry.name.clone(),
                    implementation: entry.entry.implementation.clone(),
                    decision: Decision::Deny,
                    transformed: false,
                    failed: preflight.denial.is_none(),
                });
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: preflight.reason,
                    body,
                    header_mutations,
                    findings,
                    metadata,
                    applied,
                    denial: preflight.denial,
                });
            }

            let mut body_transformed = false;
            if let Some(mut session) = preflight.session {
                let original_body = body.clone();
                let mut output = Vec::new();
                let unit_limit = session.stream_unit_limit();
                let mut failed = None;
                for chunk in body.chunks(unit_limit) {
                    match session.push_body(chunk.to_vec()).await {
                        Ok(units) => output.extend(units),
                        Err(error) => {
                            failed = Some(error);
                            break;
                        }
                    }
                }
                if let Some(error) = failed {
                    findings.extend(error.diagnostics.findings);
                    metadata.extend(error.diagnostics.metadata);
                    applied.push(MiddlewareInvocation {
                        name: entry.entry.name.clone(),
                        implementation: entry.entry.implementation.clone(),
                        decision: Decision::Deny,
                        transformed: false,
                        failed: error.denial.is_none(),
                    });
                    return Ok(ChainOutcome {
                        allowed: false,
                        reason: error.reason,
                        body: original_body,
                        header_mutations,
                        findings,
                        metadata,
                        applied,
                        denial: error.denial,
                    });
                }
                match session.finish(Vec::new()).await {
                    Ok(finish) => {
                        output.extend(finish.body_units);
                        body_transformed = finish.body_transformed;
                        stage_failed |= finish.invocations.iter().any(|item| item.failed);
                        findings.extend(finish.findings);
                        metadata.extend(finish.metadata);
                        body = output.concat();
                    }
                    Err(error) => {
                        findings.extend(error.diagnostics.findings);
                        metadata.extend(error.diagnostics.metadata);
                        applied.push(MiddlewareInvocation {
                            name: entry.entry.name.clone(),
                            implementation: entry.entry.implementation.clone(),
                            decision: Decision::Deny,
                            transformed: false,
                            failed: error.denial.is_none(),
                        });
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason: error.reason,
                            body: original_body,
                            header_mutations,
                            findings,
                            metadata,
                            applied,
                            denial: error.denial,
                        });
                    }
                }
            }

            applied.push(MiddlewareInvocation {
                name: entry.entry.name.clone(),
                implementation: entry.entry.implementation.clone(),
                decision: Decision::Allow,
                transformed: body_transformed || headers_transformed,
                failed: stage_failed,
            });

            if body_transformed
                && let TransformedBodyPolicy::Reevaluate(validate) = transformed_body_policy
            {
                let denied = match validate(&body) {
                    Ok(reason) => reason,
                    Err(error) => Some(format!(
                        "transformed_body_policy_evaluation_failed: {}",
                        safe_reason(&error.to_string())
                    )),
                };
                if let Some(reason) = denied {
                    return Ok(ChainOutcome {
                        allowed: false,
                        reason,
                        body,
                        header_mutations,
                        findings,
                        metadata,
                        applied,
                        denial: None,
                    });
                }
            }
        }

        Ok(ChainOutcome {
            allowed: true,
            reason: String::new(),
            body,
            header_mutations,
            findings,
            metadata,
            applied,
            denial: None,
        })
    }
}

/// Sort middleware by policy-defined priority. Valid policies have unique order
/// values; the name comparison only keeps direct internal callers deterministic.
pub fn sort_chain_entries(entries: &mut [ChainEntry]) {
    entries.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.name.cmp(&right.name))
    });
}

fn ensure_config_capacity(count: usize) -> Result<()> {
    if count > MAX_MIDDLEWARE_CONFIGS {
        return Err(miette!(
            "middleware config count {count} exceeds platform maximum {MAX_MIDDLEWARE_CONFIGS}"
        ));
    }
    Ok(())
}

fn ensure_chain_capacity(count: usize) -> Result<()> {
    if count > MAX_MIDDLEWARE_CHAIN_STAGES {
        return Err(miette!(
            "selected middleware stage count {count} exceeds platform maximum {MAX_MIDDLEWARE_CHAIN_STAGES}"
        ));
    }
    Ok(())
}

pub(crate) fn safe_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | ' '))
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{FutureExt, Stream, StreamExt};
    use openshell_core::proto::middleware::v1::http_request_pre_credentials_server::{
        HttpRequestPreCredentials, HttpRequestPreCredentialsServer,
    };
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
        SupervisorMiddleware, SupervisorMiddlewareServer,
    };
    use openshell_core::proto::{ExistingHeaderAction, header_mutation};
    use openshell_supervisor_middleware_builtins::{BUILTIN_REGEX, services};

    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};

    #[derive(Clone, Default)]
    struct TestRequestEvaluation {
        phase: i32,
        context: Option<RequestContext>,
        config: Option<prost_types::Struct>,
        target: Option<HttpRequestTarget>,
        headers: Vec<HttpHeader>,
        body: Vec<u8>,
        middleware_name: String,
    }

    #[derive(Clone, Default)]
    struct TestRequestResult {
        decision: i32,
        reason: String,
        body: Vec<u8>,
        has_body: bool,
        header_mutations: Vec<HeaderMutation>,
        findings: Vec<Finding>,
        metadata: HashMap<String, String>,
        reason_code: String,
    }

    type TestBodyHandler =
        Box<dyn FnOnce(Vec<u8>, TestRequestEvaluation) -> TestRequestResult + Send + 'static>;

    struct TestRequestPlan {
        preflight: TestRequestResult,
        body: Option<TestBodyHandler>,
    }

    fn constant_request_plan(result: TestRequestResult) -> TestRequestPlan {
        if result.decision != Decision::Allow as i32 {
            return TestRequestPlan {
                preflight: result,
                body: None,
            };
        }
        let preflight = TestRequestResult {
            decision: result.decision,
            header_mutations: result.header_mutations.clone(),
            ..Default::default()
        };
        TestRequestPlan {
            preflight,
            body: Some(Box::new(move |_body, _evaluation| result)),
        }
    }

    fn open_test_request_stream<F>(
        mut requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        plan: F,
    ) -> HttpRequestResultStream
    where
        F: FnOnce(openshell_core::proto::HttpRequestPreflight) -> TestRequestPlan + Send + 'static,
    {
        use openshell_core::proto::{
            HttpRequestBlock, HttpRequestBodyPassThrough, HttpRequestBodyResult,
            HttpRequestBodyTransform, HttpRequestEventResult, HttpRequestPreflightInspect,
            HttpRequestPreflightResult, HttpRequestTrailersResult, http_request_body_result,
            http_request_body_transform, http_request_event, http_request_event_result,
            http_request_preflight_result,
        };

        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let Some(openshell_core::proto::HttpRequestEvent {
                event: Some(http_request_event::Event::Preflight(preflight)),
            }) = requests.recv().await
            else {
                return;
            };
            let mut evaluation = TestRequestEvaluation {
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                context: preflight.context.clone(),
                config: preflight.config.clone(),
                target: preflight.target.clone(),
                headers: preflight.headers.clone(),
                body: Vec::new(),
                middleware_name: preflight.middleware_name.clone(),
            };
            let TestRequestPlan {
                preflight: initial,
                body,
            } = plan(preflight);
            let action = match Decision::try_from(initial.decision) {
                Ok(Decision::Deny) => Some(http_request_preflight_result::Action::BlockRequest(
                    HttpRequestBlock {},
                )),
                Ok(Decision::Allow) => Some(http_request_preflight_result::Action::Inspect(
                    HttpRequestPreflightInspect {
                        body_mode: if body.is_some() {
                            openshell_core::proto::HttpRequestBodyMode::WholeBodyBytes as i32
                        } else {
                            openshell_core::proto::HttpRequestBodyMode::HeadersOnly as i32
                        },
                        header_mutations: initial.header_mutations,
                    },
                )),
                Ok(Decision::Unspecified) | Err(_) => None,
            };
            if sender
                .send(Ok(HttpRequestEventResult {
                    result: Some(http_request_event_result::Result::PreflightResult(
                        HttpRequestPreflightResult {
                            action,
                            reason: initial.reason,
                            reason_code: initial.reason_code,
                            findings: initial.findings,
                            metadata: initial.metadata,
                        },
                    )),
                }))
                .await
                .is_err()
            {
                return;
            }

            let Some(body_handler) = body else {
                while requests.recv().await.is_some() {}
                return;
            };
            let Some(openshell_core::proto::HttpRequestEvent {
                event: Some(http_request_event::Event::Body(body)),
            }) = requests.recv().await
            else {
                return;
            };
            evaluation.body = match body.payload {
                Some(openshell_core::proto::http_request_body_unit::Payload::Data(data)) => data,
                None => Vec::new(),
            };
            let sequence = body.sequence;
            let result = body_handler(evaluation.body.clone(), evaluation);
            let action = if result.decision == Decision::Deny as i32 {
                http_request_body_result::Action::BlockRequest(HttpRequestBlock {})
            } else if result.has_body {
                http_request_body_result::Action::Transform(HttpRequestBodyTransform {
                    replacement: Some(http_request_body_transform::Replacement::Data(result.body)),
                })
            } else {
                http_request_body_result::Action::PassThrough(HttpRequestBodyPassThrough {})
            };
            if sender
                .send(Ok(HttpRequestEventResult {
                    result: Some(http_request_event_result::Result::BodyResult(
                        HttpRequestBodyResult {
                            sequence,
                            action: Some(action),
                            reason: result.reason,
                            reason_code: result.reason_code,
                            findings: result.findings,
                            metadata: result.metadata,
                        },
                    )),
                }))
                .await
                .is_err()
            {
                return;
            }
            while let Some(event) = requests.recv().await {
                match event.event {
                    Some(http_request_event::Event::Trailers(_)) => {
                        if sender
                            .send(Ok(HttpRequestEventResult {
                                result: Some(http_request_event_result::Result::TrailersResult(
                                    HttpRequestTrailersResult::default(),
                                )),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
        Box::pin(ReceiverStream::new(receiver))
    }

    fn proto_duration(value: &str) -> prost_types::Duration {
        let duration = match (value.strip_suffix("ms"), value.strip_suffix('s')) {
            (Some(milliseconds), _) => {
                Duration::from_millis(milliseconds.parse().expect("integer milliseconds"))
            }
            (_, Some(seconds)) => Duration::from_secs(seconds.parse().expect("integer seconds")),
            (None, None) => panic!("test duration must use ms or s"),
        };
        openshell_core::time::duration_from_std(duration)
            .expect("test duration is in protobuf range")
    }

    #[test]
    fn advertised_audience_mismatch_fails_registration() {
        let configured = "urn:openshell:extension:middleware:content-guard";

        // Matching and unadvertised audiences both pass.
        validate_expected_audience("content-guard", configured, "", true)
            .expect("unadvertised audience is accepted");
        validate_expected_audience("content-guard", configured, configured, true)
            .expect("matching audience is accepted");

        // Once authenticated Describe succeeds, reject a manifest that
        // contradicts the operator-owned audience configuration.
        let error =
            validate_expected_audience("content-guard", configured, "urn:example:stale", true)
                .expect_err("mismatched audience must fail closed");
        let message = error.to_string();
        assert!(message.contains("urn:example:stale"));
        assert!(message.contains(configured));

        // The check does not apply where no credential is attached at all,
        // whether because the registration opted out or because the gateway
        // has no signing key configured.
        validate_expected_audience("content-guard", configured, "urn:example:stale", false)
            .expect("an unauthenticated call has no audience to mismatch");
    }

    fn builtin_runner() -> ChainRunner {
        ChainRunner::new(
            services()
                .into_iter()
                .next()
                .expect("built-in middleware service"),
        )
    }

    fn entry(name: &str, on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: BUILTIN_REGEX.into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "mode".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("redact".into())),
                    },
                ))
                .collect(),
            },
            on_error,
        }
    }

    fn input(body: &str) -> HttpRequestInput {
        HttpRequestInput {
            request_id: "req".into(),
            sandbox_id: "sbx-id".into(),
            sandbox_name: "sbx-name".into(),
            workspace: "wrks-default".into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1".into(),
            query: String::new(),
            headers: Vec::new(),
            connection_nominated_headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn write_header(name: &str, value: &str, on_existing: ExistingHeaderAction) -> HeaderMutation {
        HeaderMutation {
            operation: Some(header_mutation::Operation::Write(
                openshell_core::proto::WriteHeader {
                    name: name.into(),
                    value: value.into(),
                    on_existing: on_existing as i32,
                },
            )),
        }
    }

    /// An in-process service that yields forever so the runtime must enforce
    /// the binding timeout around borrowed validation and evaluation futures.
    struct PendingInProcessService;

    #[tonic::async_trait]
    impl InProcessMiddleware for PendingInProcessService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/pending".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 4096,
                    request_timeout: Some(proto_duration("10ms")),
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            std::future::pending().await
        }

        async fn open_http_request_pre_credentials(
            &self,
            _requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            std::future::pending().await
        }
    }

    struct OwnedStreamService {
        invalid_finalization: bool,
    }

    #[derive(Default)]
    struct StreamSequenceRecorder {
        streams: std::sync::Mutex<Vec<Vec<(usize, bool)>>>,
    }

    struct StreamSequenceService {
        recorder: Arc<StreamSequenceRecorder>,
        findings_per_body: bool,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for StreamSequenceService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/stream-sequence".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_HTTP_REQUEST_STREAM_UNIT_BYTES as u64,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn open_http_request_pre_credentials(
            &self,
            mut requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            use openshell_core::proto::{
                HttpRequestBodyMode, HttpRequestBodyPassThrough, HttpRequestBodyResult,
                HttpRequestEventResult, HttpRequestPreflightInspect, HttpRequestPreflightResult,
                HttpRequestTrailersResult, http_request_body_result, http_request_body_unit,
                http_request_event, http_request_event_result, http_request_preflight_result,
            };

            let stream_index = {
                let mut streams = self.recorder.streams.lock().expect("stream recorder lock");
                streams.push(Vec::new());
                streams.len() - 1
            };
            let recorder = Arc::clone(&self.recorder);
            let findings_per_body = self.findings_per_body;
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let result = match event.event {
                        Some(http_request_event::Event::Preflight(_)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::PreflightResult(
                                HttpRequestPreflightResult {
                                    action: Some(http_request_preflight_result::Action::Inspect(
                                        HttpRequestPreflightInspect {
                                            body_mode: HttpRequestBodyMode::StreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        Some(http_request_event::Event::Body(body)) => {
                            let size = match body.payload {
                                Some(http_request_body_unit::Payload::Data(ref data)) => data.len(),
                                None => break,
                            };
                            recorder.streams.lock().expect("stream recorder lock")[stream_index]
                                .push((size, body.end_of_stream));
                            HttpRequestEventResult {
                                result: Some(http_request_event_result::Result::BodyResult(
                                    HttpRequestBodyResult {
                                        sequence: body.sequence,
                                        action: Some(
                                            http_request_body_result::Action::PassThrough(
                                                HttpRequestBodyPassThrough {},
                                            ),
                                        ),
                                        findings: findings_per_body
                                            .then(|| Finding {
                                                r#type: "test.stream".into(),
                                                label: "Stream finding".into(),
                                                count: 1,
                                                confidence: "high".into(),
                                                severity: "informational".into(),
                                            })
                                            .into_iter()
                                            .collect(),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        Some(http_request_event::Event::Trailers(_)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::TrailersResult(
                                HttpRequestTrailersResult::default(),
                            )),
                        },
                        Some(http_request_event::Event::SessionEnd(_)) | None => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    struct CancellationRecordingService {
        terminal: std::sync::Mutex<
            Option<tokio::sync::oneshot::Sender<openshell_core::proto::MiddlewareSessionEndReason>>,
        >,
    }

    struct BodyDenialService {
        manifest_name: String,
        deny: bool,
        session_ends: tokio::sync::mpsc::UnboundedSender<(
            String,
            openshell_core::proto::MiddlewareSessionEndReason,
        )>,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for BodyDenialService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: self.manifest_name.clone(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_HTTP_REQUEST_STREAM_UNIT_BYTES as u64,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn open_http_request_pre_credentials(
            &self,
            mut requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            use openshell_core::proto::{
                HttpRequestBlock, HttpRequestBodyMode, HttpRequestBodyPassThrough,
                HttpRequestBodyResult, HttpRequestEventResult, HttpRequestPreflightInspect,
                HttpRequestPreflightResult, http_request_body_result, http_request_event,
                http_request_event_result, http_request_preflight_result,
            };

            let name = self.manifest_name.clone();
            let deny = self.deny;
            let session_ends = self.session_ends.clone();
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let result = match event.event {
                        Some(http_request_event::Event::Preflight(_)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::PreflightResult(
                                HttpRequestPreflightResult {
                                    action: Some(http_request_preflight_result::Action::Inspect(
                                        HttpRequestPreflightInspect {
                                            body_mode: HttpRequestBodyMode::StreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        Some(http_request_event::Event::Body(body)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::BodyResult(
                                HttpRequestBodyResult {
                                    sequence: body.sequence,
                                    action: Some(if deny {
                                        http_request_body_result::Action::BlockRequest(
                                            HttpRequestBlock {},
                                        )
                                    } else {
                                        http_request_body_result::Action::PassThrough(
                                            HttpRequestBodyPassThrough {},
                                        )
                                    }),
                                    reason_code: if deny {
                                        "body_denied".into()
                                    } else {
                                        String::new()
                                    },
                                    findings: deny
                                        .then(|| Finding {
                                            r#type: "test.request-body".into(),
                                            label: "Request body denied".into(),
                                            count: 1,
                                            confidence: "high".into(),
                                            severity: "medium".into(),
                                        })
                                        .into_iter()
                                        .collect(),
                                    metadata: deny
                                        .then(|| ("rule".into(), "deny-body".into()))
                                        .into_iter()
                                        .collect(),
                                    ..Default::default()
                                },
                            )),
                        },
                        Some(http_request_event::Event::SessionEnd(end)) => {
                            if let Ok(reason) =
                                openshell_core::proto::MiddlewareSessionEndReason::try_from(
                                    end.reason,
                                )
                            {
                                let _ = session_ends.send((name.clone(), reason));
                            }
                            break;
                        }
                        Some(http_request_event::Event::Trailers(_)) | None => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for CancellationRecordingService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/cancellation-recorder".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_HTTP_REQUEST_STREAM_UNIT_BYTES as u64,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn open_http_request_pre_credentials(
            &self,
            mut requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            use openshell_core::proto::{
                HttpRequestBodyMode, HttpRequestEventResult, HttpRequestPreflightInspect,
                HttpRequestPreflightResult, http_request_event, http_request_event_result,
                http_request_preflight_result,
            };

            let terminal = self.terminal.lock().expect("terminal sender lock").take();
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                let Some(openshell_core::proto::HttpRequestEvent {
                    event: Some(http_request_event::Event::Preflight(_)),
                }) = requests.recv().await
                else {
                    return;
                };
                if sender
                    .send(Ok(HttpRequestEventResult {
                        result: Some(http_request_event_result::Result::PreflightResult(
                            HttpRequestPreflightResult {
                                action: Some(http_request_preflight_result::Action::Inspect(
                                    HttpRequestPreflightInspect {
                                        body_mode: HttpRequestBodyMode::StreamBytes as i32,
                                        header_mutations: Vec::new(),
                                    },
                                )),
                                ..Default::default()
                            },
                        )),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }
                while let Some(event) = requests.recv().await {
                    if let Some(http_request_event::Event::SessionEnd(end)) = event.event {
                        if let (Some(terminal), Ok(reason)) = (
                            terminal,
                            openshell_core::proto::MiddlewareSessionEndReason::try_from(end.reason),
                        ) {
                            let _ = terminal.send(reason);
                        }
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for OwnedStreamService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/owned-stream".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_HTTP_REQUEST_STREAM_UNIT_BYTES as u64,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn open_http_request_pre_credentials(
            &self,
            mut requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            use openshell_core::proto::{
                HttpRequestBodyFinalize, HttpRequestBodyMode, HttpRequestBodyOutput,
                HttpRequestBodyResult, HttpRequestBodyTakeOwnership, HttpRequestEventResult,
                HttpRequestPreflightInspect, HttpRequestPreflightResult, HttpRequestTrailersResult,
                http_request_body_result, http_request_event, http_request_event_result,
                http_request_preflight_result,
            };

            let invalid_finalization = self.invalid_finalization;
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let result = match event.event {
                        Some(http_request_event::Event::Preflight(_)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::PreflightResult(
                                HttpRequestPreflightResult {
                                    action: Some(http_request_preflight_result::Action::Inspect(
                                        HttpRequestPreflightInspect {
                                            body_mode: HttpRequestBodyMode::OwnedStreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        Some(http_request_event::Event::Body(body)) => {
                            let sequence = body.sequence;
                            let end_of_stream = body.end_of_stream;
                            let result = HttpRequestEventResult {
                                result: Some(http_request_event_result::Result::BodyResult(
                                    HttpRequestBodyResult {
                                        sequence,
                                        action: Some(
                                            http_request_body_result::Action::TakeOwnership(
                                                HttpRequestBodyTakeOwnership {},
                                            ),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            };
                            if sender.send(Ok(result)).await.is_err() {
                                break;
                            }
                            if end_of_stream {
                                if sender
                                    .send(Ok(HttpRequestEventResult {
                                        result: Some(
                                            http_request_event_result::Result::BodyOutput(
                                                HttpRequestBodyOutput {
                                                    sequence: 1,
                                                    data: b"signed".to_vec(),
                                                },
                                            ),
                                        ),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                if sender
                                    .send(Ok(HttpRequestEventResult {
                                        result: Some(
                                            http_request_event_result::Result::BodyFinalize(
                                                HttpRequestBodyFinalize {
                                                    through_input_sequence: if invalid_finalization
                                                    {
                                                        sequence + 1
                                                    } else {
                                                        sequence
                                                    },
                                                    through_output_sequence: 1,
                                                    reason_code: "owned_complete".into(),
                                                    findings: vec![Finding {
                                                        r#type: "test.owned".into(),
                                                        label: "Owned transformation complete"
                                                            .into(),
                                                        count: 1,
                                                        confidence: "high".into(),
                                                        severity: "informational".into(),
                                                    }],
                                                    metadata: HashMap::from([(
                                                        "mode".into(),
                                                        "owned".into(),
                                                    )]),
                                                    ..Default::default()
                                                },
                                            ),
                                        ),
                                    }))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            continue;
                        }
                        Some(http_request_event::Event::Trailers(_)) => HttpRequestEventResult {
                            result: Some(http_request_event_result::Result::TrailersResult(
                                HttpRequestTrailersResult::default(),
                            )),
                        },
                        Some(http_request_event::Event::SessionEnd(_)) | None => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    fn owned_entry(on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: "owned".into(),
            implementation: "test/owned-stream".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        }
    }

    #[tokio::test]
    async fn owned_request_stream_replaces_a_body_larger_than_the_former_unary_limit() {
        let runner = ChainRunner::new(Arc::new(OwnedStreamService {
            invalid_finalization: false,
        }));
        let body = "x".repeat(4 * 1024 * 1024 + 17);
        let mut preflight = runner
            .preflight_http_request(
                &[owned_entry(OnError::FailClosed)],
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(body.len() as u64),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("owned request preflight");
        let mut session = preflight.session.take().expect("owned request session");
        for chunk in body.as_bytes().chunks(session.stream_unit_limit()) {
            assert!(session.push_body(chunk.to_vec()).await.unwrap().is_empty());
        }
        let finish = session
            .finish(Vec::new())
            .await
            .expect("owned finalization");
        assert_eq!(finish.body_units.concat(), b"signed");
        assert!(finish.body_transformed);
        assert_eq!(finish.findings[0].middleware, "owned");
        assert_eq!(finish.findings[0].finding.r#type, "test.owned");
        assert_eq!(finish.metadata["owned"]["mode"], "owned");
    }

    #[tokio::test]
    async fn owned_request_stream_requires_fail_closed_and_valid_finalization() {
        let fail_open_runner = ChainRunner::new(Arc::new(OwnedStreamService {
            invalid_finalization: false,
        }));
        let fail_open = fail_open_runner
            .evaluate(&[owned_entry(OnError::FailOpen)], input("original"))
            .await
            .expect("fail-open evaluation");
        assert!(fail_open.allowed);
        assert_eq!(fail_open.body, b"original");
        assert!(fail_open.applied[0].failed);

        let buffered_fail_closed = ChainRunner::new(Arc::new(OwnedStreamService {
            invalid_finalization: false,
        }))
        .evaluate(&[owned_entry(OnError::FailClosed)], input("original"))
        .await
        .expect("buffered compatibility evaluation");
        assert!(!buffered_fail_closed.allowed);
        assert_eq!(
            buffered_fail_closed.reason,
            "middleware_failed: request_body_mode_not_permitted"
        );

        let invalid_runner = ChainRunner::new(Arc::new(OwnedStreamService {
            invalid_finalization: true,
        }));
        let mut preflight = invalid_runner
            .preflight_http_request(
                &[owned_entry(OnError::FailClosed)],
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(8),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("invalid finalization preflight");
        let mut session = preflight.session.take().expect("owned request session");
        assert!(
            session
                .push_body(b"original".to_vec())
                .await
                .unwrap()
                .is_empty()
        );
        let invalid = session.finish(Vec::new()).await.unwrap_err();
        assert_eq!(
            invalid.reason,
            "middleware_failed: invalid_owned_finalization"
        );
        assert!(invalid.denial.is_none());
    }

    #[tokio::test]
    async fn request_stream_stages_receive_one_empty_final_unit_only() {
        let recorder = Arc::new(StreamSequenceRecorder::default());
        let runner = ChainRunner::new(Arc::new(StreamSequenceService {
            recorder: Arc::clone(&recorder),
            findings_per_body: false,
        }));
        let entries = [
            ChainEntry {
                name: "first".into(),
                implementation: "test/stream-sequence".into(),
                order: 1,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "second".into(),
                implementation: "test/stream-sequence".into(),
                order: 2,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];
        let preflight = runner
            .preflight_http_request(
                &entries,
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(3),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("request preflight");
        let mut session = preflight.session.expect("streaming request session");
        assert_eq!(
            session.push_body(b"abc".to_vec()).await.unwrap(),
            vec![b"abc".to_vec()]
        );
        let finish = session.finish(Vec::new()).await.expect("request finish");
        assert!(finish.body_units.is_empty());

        let streams = recorder.streams.lock().expect("stream recorder lock");
        assert_eq!(
            streams.as_slice(),
            [vec![(3, false), (0, true)], vec![(3, false), (0, true)]]
        );
    }

    #[tokio::test]
    async fn request_stream_bounds_findings_across_body_results() {
        let runner = ChainRunner::new(Arc::new(StreamSequenceService {
            recorder: Arc::new(StreamSequenceRecorder::default()),
            findings_per_body: true,
        }));
        let entry = ChainEntry {
            name: "finding-stream".into(),
            implementation: "test/stream-sequence".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let preflight = runner
            .preflight_http_request(
                &[entry],
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(33),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("request preflight");
        let mut session = preflight.session.expect("streaming request session");
        for _ in 0..MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
            assert_eq!(
                session.push_body(vec![b'x']).await.unwrap(),
                vec![vec![b'x']]
            );
        }
        let failure = session
            .push_body(vec![b'x'])
            .await
            .expect_err("the aggregate finding limit must fail closed");

        assert_eq!(
            failure.reason,
            "middleware_failed: request_findings_over_capacity"
        );
        assert_eq!(
            failure.diagnostics.findings.len(),
            MAX_MIDDLEWARE_FINDINGS_PER_STAGE
        );
    }

    #[tokio::test]
    async fn request_stream_bounds_retained_invocation_records() {
        let runner = ChainRunner::new(Arc::new(StreamSequenceService {
            recorder: Arc::new(StreamSequenceRecorder::default()),
            findings_per_body: false,
        }));
        let entry = ChainEntry {
            name: "long-stream".into(),
            implementation: "test/stream-sequence".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let preflight = runner
            .preflight_http_request(
                &[entry],
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(1025),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("request preflight");
        let mut session = preflight.session.expect("streaming request session");
        for _ in 0..1025 {
            assert_eq!(
                session.push_body(vec![b'x']).await.unwrap(),
                vec![vec![b'x']]
            );
        }
        let finish = session.finish(Vec::new()).await.expect("request finish");

        assert_eq!(finish.invocations.len(), 1024);
        assert!(!finish.invocations[0].failed);
        assert!(finish.invocations[0].input_size > 1);
    }

    #[tokio::test]
    async fn dropped_request_session_sends_best_effort_cancellation() {
        let (terminal_tx, terminal_rx) = tokio::sync::oneshot::channel();
        let runner = ChainRunner::new(Arc::new(CancellationRecordingService {
            terminal: std::sync::Mutex::new(Some(terminal_tx)),
        }));
        let entry = ChainEntry {
            name: "recorder".into(),
            implementation: "test/cancellation-recorder".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let preflight = runner
            .preflight_http_request(
                &[entry],
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(1),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("request preflight");

        drop(preflight.session.expect("streaming request session"));
        let reason = tokio::time::timeout(Duration::from_secs(1), terminal_rx)
            .await
            .expect("cancellation delivery timeout")
            .expect("cancellation sender dropped");
        assert_eq!(
            reason,
            openshell_core::proto::MiddlewareSessionEndReason::Cancellation
        );
    }

    #[tokio::test]
    async fn body_denial_preserves_diagnostics_and_ends_every_open_stage() {
        use openshell_core::proto::MiddlewareSessionEndReason;

        let (session_ends_tx, mut session_ends_rx) = tokio::sync::mpsc::unbounded_channel();
        let endpoints: Vec<Arc<dyn InProcessMiddleware>> = vec![
            Arc::new(BodyDenialService {
                manifest_name: "test/body-denier".into(),
                deny: true,
                session_ends: session_ends_tx.clone(),
            }),
            Arc::new(BodyDenialService {
                manifest_name: "test/body-observer".into(),
                deny: false,
                session_ends: session_ends_tx,
            }),
        ];
        let runner = ChainRunner::from_registry(
            MiddlewareRegistry::connect_services(endpoints, Vec::new())
                .await
                .expect("connect body middleware services"),
        );
        let entries = [
            ChainEntry {
                name: "denier".into(),
                implementation: "test/body-denier".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "observer".into(),
                implementation: "test/body-observer".into(),
                order: 1,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];
        let preflight = runner
            .preflight_http_request(
                &entries,
                HttpRequestPreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget::default(),
                    declared_body_length: Some(7),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("request preflight");
        let mut session = preflight.session.expect("streaming request session");
        let failure = session
            .push_body(b"blocked".to_vec())
            .await
            .expect_err("body denial must stop the request");

        assert_eq!(failure.reason, "middleware_denied:denier:body_denied");
        assert_eq!(
            failure
                .denial
                .as_ref()
                .map(|denial| denial.config_name.as_str()),
            Some("denier")
        );
        assert_eq!(failure.diagnostics.invocations.len(), 1);
        assert_eq!(
            failure.diagnostics.invocations[0].outcome,
            HttpRequestInvocationOutcome::BlockRequest
        );
        assert_eq!(failure.diagnostics.findings.len(), 1);
        assert_eq!(failure.diagnostics.findings[0].middleware, "denier");
        assert_eq!(
            failure.diagnostics.findings[0].finding.r#type,
            "test.request-body"
        );
        assert_eq!(failure.diagnostics.metadata["denier"]["rule"], "deny-body");

        let mut ended = BTreeMap::new();
        for _ in 0..2 {
            let (name, reason) =
                tokio::time::timeout(Duration::from_secs(1), session_ends_rx.recv())
                    .await
                    .expect("session end delivery timeout")
                    .expect("session end sender dropped");
            ended.insert(name, reason);
        }
        assert_eq!(
            ended.get("test/body-denier"),
            Some(&MiddlewareSessionEndReason::MiddlewareDenial)
        );
        assert_eq!(
            ended.get("test/body-observer"),
            Some(&MiddlewareSessionEndReason::MiddlewareDenial)
        );
        assert!(session_ends_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn in_process_evaluation_remains_interruptible_by_stage_timeout() {
        let runner = ChainRunner::new(Arc::new(PendingInProcessService));
        let entry = |on_error| ChainEntry {
            name: "pending".into(),
            implementation: "test/pending".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        };
        let closed = runner
            .evaluate(&[entry(OnError::FailClosed)], input("payload"))
            .await
            .expect("timed-out in-process evaluation");
        let open = runner
            .evaluate(&[entry(OnError::FailOpen)], input("payload"))
            .await
            .expect("fail-open timed-out in-process evaluation");

        assert!(!closed.allowed);
        assert_eq!(closed.reason, "middleware_failed: middleware_timeout");
        assert!(closed.applied[0].failed);
        assert!(open.allowed);
        assert!(open.applied[0].failed);
    }

    #[tokio::test]
    async fn in_process_validation_remains_interruptible_by_binding_timeout() {
        let runner = ChainRunner::new(Arc::new(PendingInProcessService));
        let error = runner
            .validate_config("test/pending", prost_types::Struct::default())
            .await
            .expect_err("timed-out in-process validation");

        assert!(error.to_string().contains("ValidateConfig failed"));
        assert!(error.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn applies_fixed_regex_replacements() {
        let outcome = builtin_runner()
            .evaluate(
                &[entry("redact", OnError::FailClosed)],
                input(r#"{"api_key":"sk-1234567890abcdef"}"#),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"{"api_key":"[REDACTED]"}"#
        );
        assert_eq!(outcome.findings[0].finding.count, 1);
    }

    #[tokio::test]
    async fn transformed_body_feeds_next_stage() {
        let entries = [
            entry("first", OnError::FailClosed),
            entry("second", OnError::FailClosed),
        ];
        let outcome = builtin_runner()
            .evaluate(&entries, input(r#"token="sk-ABCDEFGHIJKLMNOP""#))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"token="[REDACTED]""#
        );
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(
            [
                outcome.applied[0].transformed,
                outcome.applied[1].transformed,
            ],
            [true, false]
        );
    }

    #[tokio::test]
    async fn describe_chain_sorts_by_order_then_name() {
        let mut later = entry("later", OnError::FailClosed);
        later.order = 20;
        let mut beta = entry("beta", OnError::FailClosed);
        beta.order = 10;
        let mut alpha = entry("alpha", OnError::FailClosed);
        alpha.order = 10;

        let described = builtin_runner()
            .describe_chain(&[later, beta, alpha])
            .await
            .expect("describe ordered chain");
        let names: Vec<_> = described
            .iter()
            .map(|entry| entry.entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["alpha", "beta", "later"]);
    }

    #[tokio::test]
    async fn describe_chain_accepts_maximum_selected_stages() {
        let entries: Vec<_> = (0..MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| entry(&format!("stage-{index}"), OnError::FailClosed))
            .collect();

        let described = builtin_runner()
            .describe_chain(&entries)
            .await
            .expect("maximum selected stage count");
        assert_eq!(described.len(), MAX_MIDDLEWARE_CHAIN_STAGES);
    }

    #[tokio::test]
    async fn describe_chain_rejects_selected_stages_over_capacity() {
        let entries: Vec<_> = (0..=MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| entry(&format!("stage-{index}"), OnError::FailClosed))
            .collect();

        let error = builtin_runner()
            .describe_chain(&entries)
            .await
            .err()
            .expect("selected stage count over capacity");
        assert!(
            error
                .to_string()
                .contains("selected middleware stage count 11 exceeds platform maximum 10")
        );
    }

    #[tokio::test]
    async fn fail_open_allows_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let outcome = builtin_runner()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
    }

    #[tokio::test]
    async fn fail_closed_denies_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let outcome = builtin_runner()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
    }

    #[tokio::test]
    async fn injected_service_names_drive_registration_checks() {
        let registry = MiddlewareRegistry::connect_services(services(), Vec::new())
            .await
            .expect("connect built-in service");
        let policy = SandboxPolicy {
            network_middlewares: HashMap::from([(
                "redactor".into(),
                NetworkMiddlewareConfig {
                    middleware: BUILTIN_REGEX.into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        registry
            .ensure_policy_middlewares_registered(&policy)
            .expect("described middleware is registered");
    }

    #[tokio::test]
    async fn injected_services_cannot_duplicate_middleware_names() {
        let first: Arc<dyn InProcessMiddleware> = Arc::new(PendingInProcessService);
        let second: Arc<dyn InProcessMiddleware> = Arc::new(PendingInProcessService);

        let error = MiddlewareRegistry::connect_services(vec![first, second], Vec::new())
            .await
            .expect_err("duplicate injected middleware name must fail registry construction");
        assert!(
            error
                .to_string()
                .contains("duplicate supervisor middleware name")
        );
    }

    /// A mock middleware that returns a fixed, caller-supplied result for every
    /// evaluation. Used to exercise chain behavior the built-in cannot produce
    /// (explicit deny, metadata, findings, unsafe header mutations).
    #[derive(Clone)]
    struct ScriptedService {
        manifest_name: String,
        max_body_bytes: u64,
        result: TestRequestResult,
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for ScriptedService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: self.manifest_name.clone(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: self.max_body_bytes,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            let result = self.result.clone();
            Ok(open_test_request_stream(requests, move |_| {
                constant_request_plan(result)
            }))
        }
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for ScriptedService {
        type EvaluateWebSocketSessionStream = WebSocketResponseStream;

        async fn describe(
            &self,
            request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            SupervisorMiddlewareEndpoint::describe(self, request).await
        }

        async fn validate_config(
            &self,
            request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            SupervisorMiddlewareEndpoint::validate_config(self, request).await
        }

        async fn evaluate_web_socket_session(
            &self,
            _request: Request<tonic::Streaming<openshell_core::proto::WebSocketSessionEvent>>,
        ) -> std::result::Result<tonic::Response<Self::EvaluateWebSocketSessionStream>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("HTTP-only test middleware"))
        }
    }

    #[tonic::async_trait]
    impl HttpRequestPreCredentials for ScriptedService {
        type EvaluateStream = HttpRequestResultStream;

        async fn evaluate(
            &self,
            request: Request<tonic::Streaming<openshell_core::proto::HttpRequestEvent>>,
        ) -> std::result::Result<tonic::Response<Self::EvaluateStream>, tonic::Status> {
            let (sender, receiver) = tokio::sync::mpsc::channel(4);
            let mut requests = request.into_inner();
            tokio::spawn(async move {
                while let Some(request) = requests.next().await {
                    let Ok(request) = request else {
                        break;
                    };
                    if sender.send(request).await.is_err() {
                        break;
                    }
                }
            });
            let result = self.result.clone();
            Ok(tonic::Response::new(open_test_request_stream(
                receiver,
                move |_| constant_request_plan(result),
            )))
        }
    }

    struct SlowService {
        delay: Duration,
        binding_timeout: Option<prost_types::Duration>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for SlowService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/slow".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 4096,
                    request_timeout: self.binding_timeout,
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            tokio::time::sleep(self.delay).await;
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            tokio::time::sleep(self.delay).await;
            Ok(open_test_request_stream(requests, |_| {
                constant_request_plan(allow_result())
            }))
        }
    }

    /// A middleware attached twice for exercising per-stage validation. The
    /// first policy config requests a body transformation; the second records
    /// that it ran and allows.
    struct TwoStageService {
        second_ran: Arc<std::sync::atomic::AtomicBool>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for TwoStageService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/two-stage".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 256 * 1024,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            let second_ran = Arc::clone(&self.second_ran);
            Ok(open_test_request_stream(requests, move |preflight| {
                let transform = preflight.config.as_ref().is_some_and(|config| {
                    config.fields.get("transform").is_some_and(|value| {
                        matches!(
                            value.kind.as_ref(),
                            Some(prost_types::value::Kind::BoolValue(true))
                        )
                    })
                });
                TestRequestPlan {
                    preflight: allow_result(),
                    body: Some(Box::new(move |_body, _evaluation| {
                        let mut result = allow_result();
                        if transform {
                            result.body = b"TRANSFORMED".to_vec();
                            result.has_body = true;
                        } else {
                            second_ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        }
                        result
                    })),
                }
            }))
        }
    }

    #[tokio::test]
    async fn per_stage_validation_denies_before_the_next_stage_runs() {
        // The validator rejects the first stage's transformed body. The chain
        // must stop there: the second stage never runs, so it never sees a
        // payload the policy would reject.
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddlewareEndpoint> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let transform = ChainEntry {
            name: "transform".into(),
            implementation: "test/two-stage".into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "transform".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            },
            on_error: OnError::FailClosed,
        };
        let second = ChainEntry {
            name: "second".into(),
            implementation: "test/two-stage".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let described = runner
            .describe_chain(&[transform, second])
            .await
            .expect("describe two-stage chain");

        let validator: Box<TransformedBodyValidator<'_>> = Box::new(|body: &[u8]| {
            if body == b"TRANSFORMED" {
                Ok(Some("transformed body denied by policy".to_string()))
            } else {
                Ok(None)
            }
        });
        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("evaluate two-stage chain");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "transformed body denied by policy");
        assert_eq!(outcome.applied.len(), 1, "only the first stage should run");
        assert_eq!(outcome.applied[0].name, "transform");
        assert!(
            !second_ran.load(std::sync::atomic::Ordering::SeqCst),
            "second stage must not run after a policy deny"
        );
    }

    #[tokio::test]
    async fn per_stage_validator_allows_compliant_transformations() {
        // A validator that accepts every body lets both stages run; the second
        // stage sees the first stage's output.
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddlewareEndpoint> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let transform = ChainEntry {
            name: "transform".into(),
            implementation: "test/two-stage".into(),
            order: 0,
            config: prost_types::Struct {
                fields: std::iter::once((
                    "transform".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::BoolValue(true)),
                    },
                ))
                .collect(),
            },
            on_error: OnError::FailClosed,
        };
        let second = ChainEntry {
            name: "second".into(),
            implementation: "test/two-stage".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let described = runner
            .describe_chain(&[transform, second])
            .await
            .expect("describe two-stage chain");

        let validator: Box<TransformedBodyValidator<'_>> = Box::new(|_body: &[u8]| Ok(None));
        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("evaluate two-stage chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            second_ran.load(std::sync::atomic::Ordering::SeqCst),
            "second stage should run when the transformation is compliant"
        );
    }

    #[tokio::test]
    async fn per_stage_validator_error_becomes_structured_denial() {
        let second_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let service: Arc<dyn SupervisorMiddlewareEndpoint> = Arc::new(TwoStageService {
            second_ran: Arc::clone(&second_ran),
        });
        let runner = ChainRunner::new_protobuf_for_tests(service);
        let entries = [
            ChainEntry {
                name: "transform".into(),
                implementation: "test/two-stage".into(),
                order: 0,
                config: prost_types::Struct {
                    fields: std::iter::once((
                        "transform".into(),
                        prost_types::Value {
                            kind: Some(prost_types::value::Kind::BoolValue(true)),
                        },
                    ))
                    .collect(),
                },
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "second".into(),
                implementation: "test/two-stage".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];
        let described = runner
            .describe_chain(&entries)
            .await
            .expect("describe two-stage chain");
        let validator: Box<TransformedBodyValidator<'_>> =
            Box::new(|_body: &[u8]| Err(miette!("OPA engine unavailable")));

        let outcome = runner
            .evaluate_described_with_policy(
                &described,
                input("original"),
                TransformedBodyPolicy::Reevaluate(&*validator),
            )
            .await
            .expect("policy evaluator failure should be a chain outcome");

        assert!(!outcome.allowed);
        assert!(
            outcome
                .reason
                .starts_with("transformed_body_policy_evaluation_failed:"),
            "{}",
            outcome.reason
        );
        assert_eq!(outcome.applied.len(), 1);
        assert!(!second_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    fn scripted_service(result: TestRequestResult) -> ScriptedService {
        ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 256 * 1024,
            result,
        }
    }

    fn allow_result() -> TestRequestResult {
        TestRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
            reason_code: String::new(),
        }
    }

    /// A middleware that records every evaluation it receives and allows the
    /// request, for asserting what the supervisor actually sends to services.
    struct RecordingService {
        validated: Arc<std::sync::Mutex<Vec<ValidateConfigRequest>>>,
        received: Arc<std::sync::Mutex<Vec<TestRequestEvaluation>>>,
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for RecordingService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/recorder".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            self.validated
                .lock()
                .expect("validated config lock")
                .push(request.into_inner());
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            let received = Arc::clone(&self.received);
            Ok(open_test_request_stream(requests, move |_| {
                TestRequestPlan {
                    preflight: allow_result(),
                    body: Some(Box::new(move |_body, evaluation| {
                        received.lock().expect("recording lock").push(evaluation);
                        allow_result()
                    })),
                }
            }))
        }
    }

    /// Three-stage service used to verify that each stage observes the header
    /// state produced by all preceding stages.
    struct HeaderChainService {
        second_action: ExistingHeaderAction,
        received: Arc<std::sync::Mutex<Vec<TestRequestEvaluation>>>,
    }

    struct InProcessHeaderChainService {
        received: Arc<std::sync::Mutex<Vec<Vec<HttpHeader>>>>,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for InProcessHeaderChainService {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/in-process-header-chain".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> Result<()> {
            Ok(())
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            let received = Arc::clone(&self.received);
            Ok(open_test_request_stream(requests, move |preflight| {
                let invocation = {
                    let mut received = received.lock().expect("in-process header chain lock");
                    let invocation = received.len();
                    received.push(preflight.headers);
                    invocation
                };
                let mut result = allow_result();
                if invocation == 0 {
                    result.header_mutations.push(write_header(
                        "cache-control",
                        "no-store",
                        ExistingHeaderAction::Overwrite,
                    ));
                }
                TestRequestPlan {
                    preflight: result,
                    body: None,
                }
            }))
        }
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for HeaderChainService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            Ok(tonic::Response::new(MiddlewareManifest {
                name: "test/header-chain".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn open_http_request_pre_credentials(
            &self,
            requests: tokio::sync::mpsc::Receiver<openshell_core::proto::HttpRequestEvent>,
        ) -> std::result::Result<HttpRequestResultStream, tonic::Status> {
            let received = Arc::clone(&self.received);
            let second_action = self.second_action;
            Ok(open_test_request_stream(requests, move |preflight| {
                let evaluation = TestRequestEvaluation {
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    context: preflight.context,
                    config: preflight.config,
                    target: preflight.target,
                    headers: preflight.headers,
                    body: Vec::new(),
                    middleware_name: preflight.middleware_name,
                };
                let invocation = {
                    let mut received = received.lock().expect("header chain lock");
                    let invocation = received.len();
                    received.push(evaluation);
                    invocation
                };
                let mut result = allow_result();
                if invocation == 0 {
                    result.header_mutations.push(write_header(
                        "cache-control",
                        "first",
                        ExistingHeaderAction::Overwrite,
                    ));
                } else if invocation == 1 {
                    result.header_mutations.push(write_header(
                        "cache-control",
                        "second",
                        second_action,
                    ));
                }
                TestRequestPlan {
                    preflight: result,
                    body: None,
                }
            }))
        }
    }

    #[tokio::test]
    async fn later_middleware_observes_prior_header_mutations() {
        for (action, expected) in [
            (ExistingHeaderAction::Append, vec!["first", "second"]),
            (ExistingHeaderAction::Overwrite, vec!["second"]),
            (ExistingHeaderAction::Skip, vec!["first"]),
        ] {
            let service = Arc::new(HeaderChainService {
                second_action: action,
                received: Arc::new(std::sync::Mutex::new(Vec::new())),
            });
            let runner = ChainRunner::new_protobuf_for_tests(service.clone());
            let entries = [
                ChainEntry {
                    name: "first".into(),
                    implementation: "test/header-chain".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
                ChainEntry {
                    name: "second".into(),
                    implementation: "test/header-chain".into(),
                    order: 10,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
                ChainEntry {
                    name: "observer".into(),
                    implementation: "test/header-chain".into(),
                    order: 20,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                },
            ];

            let outcome = runner
                .evaluate(&entries, input("payload"))
                .await
                .expect("evaluate header chain");
            assert!(outcome.allowed);
            let received = service.received.lock().expect("recorded header chain");
            let observed: Vec<&str> = received[2]
                .headers
                .iter()
                .filter(|header| header.name == "cache-control")
                .map(|header| header.value.as_str())
                .collect();
            assert_eq!(observed, expected, "action {action:?}");
        }
    }

    #[tokio::test]
    async fn in_process_request_middleware_writes_end_to_end_header_without_namespace() {
        let service = Arc::new(InProcessHeaderChainService {
            received: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        let runner = ChainRunner::new(service.clone());
        let entries = [
            ChainEntry {
                name: "writer".into(),
                implementation: "test/in-process-header-chain".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
            ChainEntry {
                name: "observer".into(),
                implementation: "test/in-process-header-chain".into(),
                order: 10,
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            },
        ];

        let outcome = runner
            .evaluate(&entries, input("payload"))
            .await
            .expect("evaluate in-process header chain");
        let received = service
            .received
            .lock()
            .expect("recorded in-process headers");

        assert!(outcome.allowed);
        assert_eq!(
            received[1]
                .iter()
                .filter(|header| header.name == "cache-control")
                .map(|header| header.value.as_str())
                .collect::<Vec<_>>(),
            vec!["no-store"]
        );
    }

    #[tokio::test]
    async fn repeated_request_headers_reach_middleware_in_wire_order() {
        // A map contract would collapse repeated header names to one value
        // while the upstream still receives every original value, creating an
        // inspection differential. The service must see each entry in wire
        // order.
        let service = Arc::new(RecordingService {
            validated: Arc::new(std::sync::Mutex::new(Vec::new())),
            received: Arc::new(std::sync::Mutex::new(Vec::new())),
        });
        let recorder: Arc<dyn SupervisorMiddlewareEndpoint> = service.clone();
        let runner = ChainRunner::new_protobuf_for_tests(recorder);
        let validation_config = prost_types::Struct {
            fields: std::iter::once((
                "required".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("present".into())),
                },
            ))
            .collect(),
        };
        runner
            .validate_config("test/recorder", validation_config.clone())
            .await
            .expect("validate recorder config");
        let evaluation_config = prost_types::Struct {
            fields: std::iter::once((
                "evaluation".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue("preserved".into())),
                },
            ))
            .collect(),
        };
        let recorder_entry = ChainEntry {
            name: "recorder".into(),
            implementation: "test/recorder".into(),
            order: 0,
            config: evaluation_config.clone(),
            on_error: OnError::FailClosed,
        };
        let mut request = input("payload");
        request.headers = vec![
            ("x-api-key".into(), "first-value".into()),
            ("accept".into(), "application/json".into()),
            ("x-api-key".into(), "second-value".into()),
        ];
        request.query = "page=2".into();
        let original_body = request.body.as_ptr().addr();

        let outcome = runner
            .evaluate(&[recorder_entry], request)
            .await
            .expect("evaluate recording chain");
        assert!(outcome.allowed);

        let validated = service.validated.lock().expect("validated configs");
        assert_eq!(validated.len(), 1);
        assert_eq!(validated[0].middleware_name, "test/recorder");
        assert_eq!(validated[0].config.as_ref(), Some(&validation_config));
        drop(validated);

        let received = service.received.lock().expect("recorded evaluations");
        assert_eq!(received.len(), 1);
        assert_eq!(outcome.body, b"payload");
        assert_ne!(outcome.body.as_ptr().addr(), original_body);
        assert_ne!(received[0].body.as_ptr().addr(), original_body);
        assert_eq!(received[0].body, b"payload");
        assert_eq!(
            received[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(received[0].middleware_name, "test/recorder");
        assert_eq!(received[0].config.as_ref(), Some(&evaluation_config));
        let context = received[0].context.as_ref().expect("request context");
        assert_eq!(context.request_id, "req");
        assert_eq!(context.sandbox_id, "sbx-id");
        assert_eq!(context.sandbox_name, "sbx-name");
        assert_eq!(context.workspace, "wrks-default");
        assert!(context.originating_process.is_none());
        let target = received[0].target.as_ref().expect("request target");
        assert_eq!(target.scheme, "https");
        assert_eq!(target.host, "api.example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.method, "POST");
        assert_eq!(target.path, "/v1");
        assert_eq!(target.query, "page=2");
        let headers: Vec<(&str, &str)> = received[0]
            .headers
            .iter()
            .map(|header| (header.name.as_str(), header.value.as_str()))
            .collect();
        assert_eq!(
            headers,
            vec![
                ("x-api-key", "first-value"),
                ("accept", "application/json"),
                ("x-api-key", "second-value"),
            ]
        );
    }

    fn external_registration(max_payload_bytes: u64) -> SupervisorMiddlewareService {
        SupervisorMiddlewareService {
            name: "local-guard-service".into(),
            grpc_endpoint: "http://127.0.0.1:50051".into(),
            max_payload_bytes,
            ..Default::default()
        }
    }

    async fn registry_with_external(
        service: Arc<dyn SupervisorMiddlewareEndpoint>,
        registration: SupervisorMiddlewareService,
    ) -> MiddlewareRegistry {
        let builtin_service = services()
            .into_iter()
            .next()
            .expect("built-in middleware service");
        let builtin_manifest = builtin_service.describe().await;
        validate_manifest_bindings("test built-in service", &builtin_manifest, None)
            .expect("valid built-in manifest");
        let builtin_name = builtin_manifest.name.clone();
        let builtin_manifest_cell = OnceCell::new();
        builtin_manifest_cell
            .set(builtin_manifest)
            .expect("built-in manifest cache");

        let manifest = service
            .describe(Request::new(()))
            .await
            .expect("describe test service")
            .into_inner();
        let operator_max_payload_bytes = usize::try_from(registration.max_payload_bytes).unwrap();
        let operator_timeout = validate_registration(&registration).expect("valid registration");
        validate_external_manifest(&registration, &manifest, operator_max_payload_bytes, false)
            .expect("valid external manifest");
        let manifest_cell = OnceCell::new();
        manifest_cell.set(manifest).expect("manifest cache");
        let registration_name = registration.name.clone();
        MiddlewareRegistry {
            services: Arc::new(vec![
                Arc::new(MiddlewareServiceState {
                    attachment_name: Some(builtin_name.clone()),
                    service: MiddlewareDispatch::InProcess(builtin_service),
                    manifest: builtin_manifest_cell,
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Preserve,
                    operator_max_payload_bytes: None,
                    operator_timeout: DEFAULT_MIDDLEWARE_TIMEOUT,
                }),
                Arc::new(MiddlewareServiceState {
                    attachment_name: Some(registration_name.clone()),
                    service: MiddlewareDispatch::Grpc(remote::GrpcMiddlewareService::from_service(
                        service,
                    )),
                    manifest: manifest_cell,
                    diagnostic_policy: MiddlewareDiagnosticPolicy::Normalize,
                    operator_max_payload_bytes: Some(operator_max_payload_bytes),
                    operator_timeout,
                }),
            ]),
            registered_services: Arc::new(vec![RegisteredMiddlewareService { registration }]),
            middleware_names: Arc::new(HashSet::from([builtin_name, registration_name])),
            work_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_WORK)),
            work_admission_waiters: Arc::new(Semaphore::new(MAX_QUEUED_MIDDLEWARE_WORK)),
            session_admission: Arc::new(Semaphore::new(MAX_CONCURRENT_MIDDLEWARE_SESSIONS)),
        }
    }

    #[tokio::test]
    async fn describe_chain_marks_resolved_and_unresolved_entries() {
        let unresolved = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let described = builtin_runner()
            .describe_chain(&[entry("redact", OnError::FailClosed), unresolved])
            .await
            .expect("describe chain");
        // The built-in resolves and reports its real limit; the missing binding
        // does not resolve and must not contribute a body limit.
        assert!(described[0].is_resolved());
        assert_eq!(described[0].max_payload_bytes(), 256 * 1024);
        assert!(!described[1].is_resolved());
    }

    #[tokio::test]
    async fn descriptors_are_resolved_from_any_middleware_service() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        }));
        let entry = ChainEntry {
            name: "external".into(),
            implementation: "test/middleware".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&entry))
            .await
            .expect("describe external middleware");
        assert_eq!(described[0].max_payload_bytes(), 4096);
        assert_eq!(
            described[0]
                .binding
                .as_ref()
                .expect("described binding")
                .phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );

        let outcome = runner
            .evaluate_described(&described, input("hello"))
            .await
            .expect("evaluate external middleware");
        assert!(outcome.allowed);
    }

    #[tokio::test]
    async fn mixed_builtin_and_external_chain_uses_operator_limit() {
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let external_entry = ChainEntry {
            name: "external".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let entries = [entry("builtin", OnError::FailClosed), external_entry];

        let described = runner
            .describe_chain(&entries)
            .await
            .expect("describe chain");
        assert_eq!(described[0].max_payload_bytes(), 256 * 1024);
        assert_eq!(described[1].max_payload_bytes(), 1024);

        let outcome = runner
            .evaluate_described(&described, input(r#"token="sk-ABCDEFGHIJKLMNOP""#))
            .await
            .expect("evaluate mixed chain");
        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"token="[REDACTED]""#
        );
    }

    #[tokio::test]
    async fn undersized_stage_fails_open_while_later_stage_runs() {
        // A body over one stage's limit must fail only that stage through its
        // own `on_error`, not the whole chain: the 1 KiB fail-open guard is
        // skipped while the 256 KiB fail-closed redactor still runs.
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let guard_entry = ChainEntry {
            name: "guard".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let mut redact_entry = entry("redact", OnError::FailClosed);
        redact_entry.order = 10;
        let entries = [guard_entry, redact_entry];

        let body = format!("{}token=\"sk-ABCDEFGHIJKLMNOP\"", "x".repeat(1500));
        let outcome = runner
            .evaluate(&entries, input(&body))
            .await
            .expect("evaluate mixed-limit chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            outcome.applied[0].failed,
            "undersized guard must be skipped"
        );
        assert_eq!(outcome.applied[0].decision, Decision::Allow);
        assert!(!outcome.applied[1].failed);
        assert!(outcome.applied[1].transformed);
        let body = String::from_utf8(outcome.body).expect("utf8");
        assert!(body.contains("[REDACTED]"));
        assert!(!body.contains("sk-ABCDEFGHIJKLMNOP"));
    }

    #[tokio::test]
    async fn transformed_body_still_over_later_stage_capacity_honors_on_error() {
        // Per-stage capacity applies to the current body: the redactor's
        // replacement is still over the 1 KiB guard limit, so the fail-closed
        // guard denies through its own `on_error` after the redactor ran.
        let external = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        });
        let registry = registry_with_external(external, external_registration(1024)).await;
        let runner = ChainRunner::from_registry(registry);
        let guard_entry = ChainEntry {
            name: "guard".into(),
            implementation: "local-guard-service".into(),
            order: 10,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let entries = [entry("redact", OnError::FailClosed), guard_entry];

        let body = format!("{}token=\"sk-ABCDEFGHIJKLMNOP\"", "x".repeat(1500));
        let outcome = runner
            .evaluate(&entries, input(&body))
            .await
            .expect("evaluate mixed-limit chain");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: request_body_mode_not_permitted"
        );
        assert_eq!(outcome.applied.len(), 2);
        assert!(
            outcome.applied[0].transformed,
            "redactor ran before the deny"
        );
        assert!(outcome.applied[1].failed);
    }

    #[test]
    fn external_manifest_rejects_operator_limit_above_capability() {
        let registration = external_registration(4097);
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: HTTP_REQUEST_OPERATION as i32,
                phase: PRE_CREDENTIALS_PHASE as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
        };
        let error = validate_external_manifest(&registration, &manifest, 4097, false)
            .expect_err("operator limit must fit capability");
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn external_registration_rejects_payload_limit_above_platform_maximum() {
        let registration = external_registration(u64::MAX);
        let error = validate_registration(&registration)
            .expect_err("extreme payload limit must be rejected before allocation");
        assert!(error.to_string().contains("platform maximum"));
    }

    #[test]
    fn manifest_rejects_payload_limit_above_platform_maximum() {
        let registration = external_registration(4096);
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: HTTP_REQUEST_OPERATION as i32,
                phase: PRE_CREDENTIALS_PHASE as i32,
                max_payload_bytes: u64::MAX,
                request_timeout: None,
            }],
            expected_audience: String::new(),
        };
        let error = validate_external_manifest(&registration, &manifest, 4096, false)
            .expect_err("extreme advertised payload limit must be rejected");
        assert!(error.to_string().contains("platform maximum"));
    }

    #[test]
    fn manifest_rejects_duplicate_operation_phase_pairs() {
        let registration = external_registration(4096);
        let binding = || MiddlewareBinding {
            operation: HTTP_REQUEST_OPERATION as i32,
            phase: PRE_CREDENTIALS_PHASE as i32,
            max_payload_bytes: 4096,
            request_timeout: None,
        };
        let manifest = MiddlewareManifest {
            name: "example/service".into(),
            service_version: "test".into(),
            bindings: vec![binding(), binding()],
            expected_audience: String::new(),
        };

        let error = validate_external_manifest(&registration, &manifest, 4096, false)
            .expect_err("one service cannot advertise two bindings for the same pair");
        assert!(
            error
                .to_string()
                .contains("duplicate middleware operation/phase pair")
        );
    }

    #[test]
    fn manifest_accepts_http_response_pre_return_binding_when_dispatch_is_available() {
        let registration = external_registration(4096);
        let manifest = MiddlewareManifest {
            name: "example/response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 4096,
                request_timeout: Some(prost_types::Duration {
                    seconds: 0,
                    nanos: 500_000_000,
                }),
            }],
            expected_audience: String::new(),
        };

        validate_external_manifest(&registration, &manifest, 4096, false)
            .expect("HTTP response pre-return binding is supported");
    }

    #[test]
    fn external_manifest_rejects_post_credentials_binding() {
        let registration = external_registration(4096);
        let manifest = MiddlewareManifest {
            name: "example/credential-visible".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PostCredentials as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
        };

        let error = validate_external_manifest(&registration, &manifest, 4096, true)
            .expect_err("external middleware must never observe resolved credentials");
        assert!(
            error
                .to_string()
                .contains("reserved for trusted in-process")
        );
    }

    #[test]
    fn manifest_accepts_forward_websocket_binding_and_reserves_return_phase() {
        let binding = |phase| MiddlewareBinding {
            operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
            phase: phase as i32,
            max_payload_bytes: MAX_MIDDLEWARE_PAYLOAD_BYTES as u64,
            request_timeout: Some(proto_duration("500ms")),
        };
        let mut manifest = MiddlewareManifest {
            name: "example/websocket".into(),
            service_version: "test".into(),
            bindings: vec![binding(SupervisorMiddlewarePhase::PreCredentials)],
            expected_audience: String::new(),
        };
        validate_manifest_bindings("test WebSocket service", &manifest, None)
            .expect("forward WebSocket binding is supported");

        manifest.bindings = vec![binding(SupervisorMiddlewarePhase::PreReturn)];
        let error = validate_manifest_bindings("test WebSocket service", &manifest, None)
            .expect_err("return-path WebSocket binding is not yet supported");
        assert!(error.to_string().contains("not yet supported"));
    }

    #[test]
    fn external_websocket_binding_requires_operator_payload_limit() {
        let registration = external_registration(0);
        let manifest = MiddlewareManifest {
            name: "example/websocket".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
        };

        let error = validate_external_manifest(&registration, &manifest, 0, false)
            .expect_err("WebSocket bindings require an operator payload ceiling");
        assert!(
            error
                .to_string()
                .contains("must configure max_payload_bytes")
        );
    }

    #[test]
    fn external_websocket_binding_rejects_operator_limit_above_capability() {
        let registration = external_registration(4097);
        let manifest = MiddlewareManifest {
            name: "example/websocket".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
        };

        let error = validate_external_manifest(&registration, &manifest, 4097, false)
            .expect_err("operator payload limit must fit WebSocket capability");
        assert!(error.to_string().contains("exceeds"));
    }

    #[test]
    fn external_registration_accepts_http_and_https_grpc_endpoints() {
        for grpc_endpoint in [
            "http://127.0.0.1:50051",
            "https://middleware.example.com:443",
        ] {
            let mut registration = external_registration(4096);
            registration.grpc_endpoint = grpc_endpoint.into();
            validate_registration(&registration).expect("supported gRPC endpoint scheme");
        }
    }

    #[test]
    fn external_registration_rejects_unsupported_grpc_endpoint_scheme() {
        let mut registration = external_registration(4096);
        registration.grpc_endpoint = "ftp://middleware.example.com".into();
        let error = validate_registration(&registration).expect_err("unsupported scheme");
        assert!(error.to_string().contains("http:// or https://"));
    }

    #[test]
    fn external_registration_name_is_stable_and_cannot_shadow_builtins() {
        for name in ["", "guard\nforged", "openshell/regex"] {
            let mut registration = external_registration(4096);
            registration.name = name.into();
            assert!(
                validate_registration(&registration).is_err(),
                "registration name {name:?} must be rejected"
            );
        }
    }

    #[test]
    fn registration_timeout_uses_default_and_operator_override() {
        let registration = external_registration(4096);
        let timeout = validate_registration(&registration).expect("default timeout");
        assert_eq!(timeout, DEFAULT_MIDDLEWARE_TIMEOUT);

        let mut registration = external_registration(4096);
        registration.request_timeout = Some(proto_duration("2s"));
        let timeout = validate_registration(&registration).expect("operator timeout");
        assert_eq!(timeout, Duration::from_secs(2));
    }

    #[test]
    fn registration_timeout_enforces_bounds() {
        for timeout in ["9ms", "31s"] {
            let mut registration = external_registration(4096);
            registration.request_timeout = Some(proto_duration(timeout));
            assert!(validate_registration(&registration).is_err());
        }
    }

    #[test]
    fn manifest_binding_timeout_enforces_bounds() {
        let registration = external_registration(4096);
        for timeout in ["9ms", "31s"] {
            let manifest = MiddlewareManifest {
                name: "example/service".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: HTTP_REQUEST_OPERATION as i32,
                    phase: PRE_CREDENTIALS_PHASE as i32,
                    max_payload_bytes: 4096,
                    request_timeout: Some(proto_duration(timeout)),
                }],
                expected_audience: String::new(),
            };
            let error = validate_external_manifest(&registration, &manifest, 4096, false)
                .expect_err("out-of-bounds binding timeout must be rejected");
            assert!(error.to_string().contains("invalid timeout"));
        }
    }

    #[tokio::test]
    async fn binding_timeout_override_controls_evaluation_and_on_error() {
        let mut registration = external_registration(4096);
        registration.request_timeout = Some(proto_duration("2s"));
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: Some(proto_duration("10ms")),
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = |on_error| ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error,
        };

        let described = runner
            .describe_chain(&[slow_entry(OnError::FailClosed)])
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let closed = runner
            .evaluate(&[slow_entry(OnError::FailClosed)], input("payload"))
            .await
            .expect("fail-closed timeout outcome");
        assert!(!closed.allowed);
        assert_eq!(closed.reason, "middleware_failed: middleware_timeout");

        let open = runner
            .evaluate(&[slow_entry(OnError::FailOpen)], input("payload"))
            .await
            .expect("fail-open timeout outcome");
        assert!(open.allowed);
        assert!(open.applied[0].failed);
    }

    #[tokio::test]
    async fn operator_timeout_controls_binding_without_manifest_override() {
        let mut registration = external_registration(4096);
        registration.request_timeout = Some(proto_duration("10ms"));
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: None,
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&slow_entry))
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let outcome = runner
            .evaluate(&[slow_entry], input("payload"))
            .await
            .expect("operator timeout outcome");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: middleware_timeout");
    }

    #[tokio::test]
    async fn operator_timeout_caps_longer_binding_timeout_for_validation_and_evaluation() {
        let mut registration = external_registration(4096);
        registration.request_timeout = Some(proto_duration("10ms"));
        let registry = registry_with_external(
            Arc::new(SlowService {
                delay: Duration::from_millis(50),
                binding_timeout: Some(prost_types::Duration {
                    seconds: 2,
                    nanos: 0,
                }),
            }),
            registration,
        )
        .await;
        let runner = ChainRunner::from_registry(registry);
        let slow_entry = ChainEntry {
            name: "slow".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };

        let described = runner
            .describe_chain(std::slice::from_ref(&slow_entry))
            .await
            .expect("describe slow binding");
        assert_eq!(described[0].timeout(), Duration::from_millis(10));

        let validation_error = runner
            .validate_config("local-guard-service", prost_types::Struct::default())
            .await
            .expect_err("operator timeout must cap ValidateConfig");
        assert!(
            validation_error
                .to_string()
                .contains("ValidateConfig failed")
        );
        assert!(validation_error.to_string().contains("timed out"));

        let outcome = runner
            .evaluate(&[slow_entry], input("payload"))
            .await
            .expect("operator-capped evaluation outcome");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_failed: middleware_timeout");
    }

    #[tokio::test]
    async fn external_registry_attaches_same_service_under_multiple_names() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let service = ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        };
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service.clone()))
            .add_service(HttpRequestPreCredentialsServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let mut second_registration = registration.clone();
        second_registration.name = "secondary-guard-service".into();
        let registry = MiddlewareRegistry::connect_services(
            Vec::new(),
            vec![registration.clone(), second_registration.clone()],
        )
        .await
        .expect("connect the same external middleware binding under two names");
        let policy = SandboxPolicy {
            network_middlewares: HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    name: String::new(),
                    middleware: "local-guard-service".into(),
                    order: 0,
                    config: Some(prost_types::Struct::default()),
                    on_error: "fail_closed".into(),
                    endpoints: None,
                },
            )]),
            ..Default::default()
        };

        registry
            .validate_policy_configs(&policy)
            .await
            .expect("remote config validates");
        assert_eq!(
            registry.required_services(Some(&policy)),
            vec![registration.clone()]
        );

        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[
                    ChainEntry {
                        name: "primary".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    },
                    ChainEntry {
                        name: "secondary".into(),
                        implementation: "secondary-guard-service".into(),
                        order: 10,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    },
                ],
                input("hello"),
            )
            .await
            .expect("remote evaluation");
        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), 2);
        assert_eq!(outcome.applied[0].implementation, registration.name);
        assert_eq!(outcome.applied[1].implementation, second_registration.name);

        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve");
    }

    #[tokio::test]
    async fn remote_transport_accepts_maximum_bounded_request_and_response_envelopes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test middleware");
        let address = listener.local_addr().expect("test middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let response_findings = (0..MAX_MIDDLEWARE_FINDINGS_PER_STAGE)
            .map(|_| Finding {
                r#type: "f".repeat(1024),
                label: "finding".into(),
                count: 1,
                confidence: "medium".into(),
                severity: "medium".into(),
            })
            .collect();
        let service = ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: MAX_MIDDLEWARE_PAYLOAD_BYTES as u64,
            result: TestRequestResult {
                reason: "r".repeat(MAX_MIDDLEWARE_REASON_BYTES - 128),
                reason_code: "r".repeat(MAX_MIDDLEWARE_REASON_CODE_BYTES),
                body: vec![b'x'; MAX_MIDDLEWARE_PAYLOAD_BYTES],
                has_body: true,
                header_mutations: vec![write_header(
                    "x-openshell-middleware-envelope",
                    &"h".repeat(headers::MAX_HEADER_MUTATION_BYTES - 128),
                    ExistingHeaderAction::Append,
                )],
                findings: response_findings,
                metadata: std::iter::once((
                    "diagnostic".into(),
                    "m".repeat(MAX_MIDDLEWARE_METADATA_BYTES - 128),
                ))
                .collect(),
                ..allow_result()
            },
        };
        let server = tonic::transport::Server::builder()
            .add_service(
                SupervisorMiddlewareServer::new(service.clone())
                    .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                    .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            )
            .add_service(
                HttpRequestPreCredentialsServer::new(service)
                    .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                    .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(MAX_MIDDLEWARE_PAYLOAD_BYTES as u64);
        registration.grpc_endpoint = format!("http://{address}");
        let registry = MiddlewareRegistry::connect_services(Vec::new(), vec![registration])
            .await
            .expect("connect external middleware");
        let config = prost_types::Struct {
            fields: std::iter::once((
                "payload".into(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(
                        "c".repeat(MAX_MIDDLEWARE_CONFIG_BYTES - 256),
                    )),
                },
            ))
            .collect(),
        };
        assert!(config.encoded_len() <= MAX_MIDDLEWARE_CONFIG_BYTES);
        let mut request = input("");
        request.request_id = "r".repeat(MAX_MIDDLEWARE_CONTEXT_BYTES - 256);
        request.path = format!("/{}", "p".repeat(MAX_MIDDLEWARE_TARGET_BYTES - 512));
        request.headers = vec![(
            "x-large-envelope".into(),
            "v".repeat(MAX_MIDDLEWARE_HEADER_BYTES - 256),
        )];
        request.body = vec![b'b'; MAX_MIDDLEWARE_PAYLOAD_BYTES];
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config,
                    on_error: OnError::FailClosed,
                }],
                request,
            )
            .await
            .expect("maximum bounded envelopes should fit configured transport limit");

        assert!(outcome.allowed);
        assert_eq!(outcome.body.len(), MAX_MIDDLEWARE_PAYLOAD_BYTES);
        assert_eq!(outcome.header_mutations.len(), 1);
        assert_eq!(outcome.findings.len(), MAX_MIDDLEWARE_FINDINGS_PER_STAGE);
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve");
    }

    #[test]
    fn grpc_envelope_headroom_matches_bounded_components() {
        assert_eq!(MIDDLEWARE_GRPC_ENVELOPE_BYTES, 292 * 1024 + 64);
        assert_eq!(
            MIDDLEWARE_GRPC_MESSAGE_BYTES,
            MAX_MIDDLEWARE_PAYLOAD_BYTES + 292 * 1024 + 64
        );
    }

    #[tokio::test]
    async fn external_diagnostics_are_normalized_before_reaching_logs() {
        let secret = "sk-secret-request-value";
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: TestRequestResult {
                decision: Decision::Deny as i32,
                reason: format!("denied body={secret}\nFINDING:FORGED"),
                reason_code: "content_match".into(),
                findings: vec![Finding {
                    r#type: format!("secret.{secret}\nforged"),
                    label: format!("matched {secret}\nFINDING:FORGED"),
                    count: 1,
                    confidence: secret.into(),
                    severity: "high\nFINDING:FORGED".into(),
                }],
                metadata: std::iter::once(("request".into(), secret.into())).collect(),
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input("hello"),
            )
            .await
            .expect("evaluate external middleware");

        assert_eq!(outcome.reason, "middleware_denied:guard:content_match");
        assert_eq!(
            outcome.denial,
            Some(MiddlewareDenial {
                config_name: "guard".into(),
                reason_code: Some("content_match".into()),
            })
        );
        assert_eq!(
            outcome.findings[0].finding.r#type,
            "local-guard-service.finding"
        );
        assert_eq!(outcome.findings[0].finding.label, EXTERNAL_FINDING_LABEL);
        assert_eq!(outcome.findings[0].finding.severity, "medium");
        assert!(outcome.metadata.is_empty());
        assert!(!format!("{outcome:?}").contains(secret));
        assert!(!format!("{outcome:?}").contains("FINDING:FORGED"));
    }

    #[tokio::test]
    async fn invalid_reason_code_is_a_middleware_failure() {
        let runner =
            ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(TestRequestResult {
                decision: Decision::Deny as i32,
                reason_code: "Secret value!".into(),
                ..allow_result()
            })));
        let outcome = runner
            .evaluate(
                &[entry("content-guard", OnError::FailClosed)],
                input("hello"),
            )
            .await
            .expect("evaluate invalid reason code");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: request_reason_code_invalid"
        );
        assert!(outcome.denial.is_none());
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn external_header_mutation_failure_uses_platform_reason() {
        let secret = "sk-secret-request-value";
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: TestRequestResult {
                header_mutations: vec![write_header(
                    &format!("x-openshell-middleware-invalid\n{secret}"),
                    "value",
                    ExistingHeaderAction::Append,
                )],
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let outcome = ChainRunner::from_registry(registry)
            .evaluate(
                &[ChainEntry {
                    name: "guard".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                input("hello"),
            )
            .await
            .expect("evaluate external middleware");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: header_mutation_invalid_name"
        );
        assert!(outcome.findings.is_empty());
        assert!(!format!("{outcome:?}").contains(secret));
    }

    #[tokio::test]
    async fn credential_placeholder_header_mutation_follows_on_error() {
        let placeholder = "openshell:resolve:env:API_KEY";
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: TestRequestResult {
                header_mutations: vec![write_header(
                    "x-api-key",
                    placeholder,
                    ExistingHeaderAction::Overwrite,
                )],
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, external_registration(4096)).await;
        let runner = ChainRunner::from_registry(registry);

        for (on_error, allowed) in [(OnError::FailClosed, false), (OnError::FailOpen, true)] {
            let outcome = runner
                .evaluate(
                    &[ChainEntry {
                        name: "guard".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error,
                    }],
                    input("hello"),
                )
                .await
                .expect("evaluate credential placeholder mutation");

            assert_eq!(outcome.allowed, allowed);
            assert!(outcome.header_mutations.is_empty());
            assert_eq!(outcome.applied.len(), 1);
            assert!(outcome.applied[0].failed);
            assert!(!format!("{outcome:?}").contains(placeholder));
            if !allowed {
                assert_eq!(
                    outcome.reason,
                    "middleware_failed: header_mutation_credential_placeholder"
                );
            }
        }
    }

    #[tokio::test]
    async fn connection_nominated_write_and_remove_are_rejected_after_filtering() {
        let mutations = [
            write_header(
                "x-openshell-middleware-tag",
                "value",
                ExistingHeaderAction::Append,
            ),
            HeaderMutation {
                operation: Some(header_mutation::Operation::Remove(
                    openshell_core::proto::RemoveHeader {
                        name: "x-openshell-middleware-tag".into(),
                    },
                )),
            },
        ];

        for mutation in mutations {
            let service = Arc::new(ScriptedService {
                manifest_name: "test/middleware".into(),
                max_body_bytes: 4096,
                result: TestRequestResult {
                    header_mutations: vec![mutation],
                    ..allow_result()
                },
            });
            let registry = registry_with_external(service, external_registration(4096)).await;
            let mut request = input("hello");
            request.connection_nominated_headers = vec!["x-openshell-middleware-tag".into()];

            let outcome = ChainRunner::from_registry(registry)
                .evaluate(
                    &[ChainEntry {
                        name: "guard".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error: OnError::FailClosed,
                    }],
                    request,
                )
                .await
                .expect("evaluate external middleware");

            assert!(!outcome.allowed);
            assert_eq!(
                outcome.reason,
                "middleware_failed: header_mutation_hop_by_hop_header"
            );
        }
    }

    #[tokio::test]
    async fn finding_overflow_is_an_invalid_response_governed_by_on_error() {
        let registration = external_registration(4096);
        let service = Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: TestRequestResult {
                findings: vec![Finding::default(); MAX_MIDDLEWARE_FINDINGS_PER_STAGE + 1],
                ..allow_result()
            },
        });
        let registry = registry_with_external(service, registration).await;
        let runner = ChainRunner::from_registry(registry);

        for (on_error, allowed) in [(OnError::FailClosed, false), (OnError::FailOpen, true)] {
            let outcome = runner
                .evaluate(
                    &[ChainEntry {
                        name: "guard".into(),
                        implementation: "local-guard-service".into(),
                        order: 0,
                        config: prost_types::Struct::default(),
                        on_error,
                    }],
                    input("hello"),
                )
                .await
                .expect("evaluate finding overflow");

            assert_eq!(outcome.allowed, allowed);
            assert!(outcome.findings.is_empty());
            assert_eq!(outcome.applied.len(), 1);
            assert!(outcome.applied[0].failed);
            if !allowed {
                assert_eq!(
                    outcome.reason,
                    "middleware_failed: request_findings_over_capacity"
                );
            }
        }
    }

    #[tokio::test]
    async fn maximum_chain_retains_findings_from_every_stage() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: "test/middleware".into(),
            max_body_bytes: 4096,
            result: TestRequestResult {
                findings: vec![
                    Finding {
                        r#type: "example.finding".into(),
                        label: "Example finding".into(),
                        count: 1,
                        confidence: String::new(),
                        severity: "medium".into(),
                    };
                    MAX_MIDDLEWARE_FINDINGS_PER_STAGE
                ],
                ..allow_result()
            },
        }));
        let entries: Vec<_> = (0..MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| ChainEntry {
                name: format!("guard-{index}"),
                implementation: "test/middleware".into(),
                order: i32::try_from(index).expect("bounded stage index"),
                config: prost_types::Struct::default(),
                on_error: OnError::FailClosed,
            })
            .collect();

        let outcome = runner
            .evaluate(&entries, input("hello"))
            .await
            .expect("evaluate maximum chain");

        assert!(outcome.allowed);
        assert_eq!(outcome.applied.len(), MAX_MIDDLEWARE_CHAIN_STAGES);
        assert_eq!(outcome.findings.len(), MAX_MIDDLEWARE_CHAIN_FINDINGS);
        for (stage, findings) in outcome
            .findings
            .chunks_exact(MAX_MIDDLEWARE_FINDINGS_PER_STAGE)
            .enumerate()
        {
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.middleware == format!("guard-{stage}"))
            );
        }
    }

    #[tokio::test]
    async fn deny_decision_short_circuits_chain() {
        let runner =
            ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(TestRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                ..allow_result()
            })));
        let outcome = runner
            .evaluate(
                &[
                    entry("first", OnError::FailClosed),
                    entry("second", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:first");
        assert_eq!(
            outcome.denial,
            Some(MiddlewareDenial {
                config_name: "first".into(),
                reason_code: None,
            })
        );
        assert!(!format!("{outcome:?}").contains("blocked_by_policy"));
        // The deny short-circuits the chain: the second middleware never runs.
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn deny_decision_ignores_unsafe_mutations_under_fail_open() {
        let runner =
            ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(TestRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                header_mutations: vec![write_header(
                    "x-openshell-middleware-inject",
                    "ok\r\nHost: evil",
                    ExistingHeaderAction::Append,
                )],
                ..allow_result()
            })));

        let outcome = runner
            .evaluate(&[entry("guard", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:guard");
        assert!(outcome.header_mutations.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn deny_decision_ignores_oversized_replacement_under_fail_open() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: TestRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                body: b"too large".to_vec(),
                has_body: true,
                ..allow_result()
            },
        }));

        let outcome = runner
            .evaluate(&[entry("guard", OnError::FailOpen)], input("safe"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "middleware_denied:guard");
        assert_eq!(outcome.body, b"safe");
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].transformed);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn metadata_and_findings_are_namespaced_per_config() {
        let runner =
            ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(TestRequestResult {
                findings: vec![Finding {
                    r#type: "pii.email".into(),
                    label: "email address".into(),
                    count: 2,
                    confidence: "high".into(),
                    severity: "medium".into(),
                }],
                metadata: std::iter::once(("sensitivity".to_string(), "high".to_string()))
                    .collect(),
                ..allow_result()
            })));
        let outcome = runner
            .evaluate(
                &[
                    entry("alpha", OnError::FailClosed),
                    entry("beta", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        // Metadata is bucketed under each config's local name, so two configs
        // emitting the same key do not collide.
        assert_eq!(outcome.metadata["alpha"]["sensitivity"], "high");
        assert_eq!(outcome.metadata["beta"]["sensitivity"], "high");
        // Findings are tagged with the emitting config's name.
        assert_eq!(outcome.findings.len(), 2);
        assert_eq!(outcome.findings[0].middleware, "alpha");
        assert_eq!(outcome.findings[1].middleware, "beta");
        assert_eq!(outcome.findings[0].finding.r#type, "pii.email");
        assert_eq!(outcome.findings[0].finding.count, 2);
    }

    fn unsafe_header_service() -> ScriptedService {
        scripted_service(TestRequestResult {
            header_mutations: vec![
                write_header(
                    "x-openshell-middleware-safe",
                    "safe",
                    ExistingHeaderAction::Append,
                ),
                write_header(
                    "x-openshell-middleware-inject",
                    "ok\r\nHost: evil",
                    ExistingHeaderAction::Append,
                ),
            ],
            ..allow_result()
        })
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_closed_denies() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
        // The deny reason names the offending header so operators can fix the
        // service without reading supervisor source.
        assert!(
            outcome.reason.contains("x-openshell-middleware-inject"),
            "reason should name the offending header: {}",
            outcome.reason
        );
        assert!(outcome.applied.iter().any(|inv| inv.failed));
        // The stage is atomic: neither the unsafe mutation nor the safe
        // mutation preceding it is forwarded.
        assert!(outcome.header_mutations.is_empty());
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_open_continues() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
        assert!(outcome.header_mutations.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn oversized_replacement_body_honors_on_error() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: TestRequestResult {
                body: b"too large".to_vec(),
                has_body: true,
                ..allow_result()
            },
        }));
        let fail_open = entry("small", OnError::FailOpen);
        let mut fail_closed = fail_open.clone();
        fail_closed.on_error = OnError::FailClosed;

        let open_outcome = runner
            .evaluate(&[fail_open], input("safe"))
            .await
            .expect("fail-open evaluation");
        assert!(open_outcome.allowed);
        assert_eq!(open_outcome.body, b"safe");
        assert!(open_outcome.applied[0].failed);

        let closed_outcome = runner
            .evaluate(&[fail_closed], input("safe"))
            .await
            .expect("fail-closed evaluation");
        assert!(!closed_outcome.allowed);
        assert_eq!(
            closed_outcome.reason,
            "middleware_failed: body_replacement_over_capacity"
        );
        assert!(closed_outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn oversized_request_body_honors_on_error() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: BUILTIN_REGEX.into(),
            max_body_bytes: 4,
            result: allow_result(),
        }));
        let fail_open = entry("small", OnError::FailOpen);
        let mut fail_closed = fail_open.clone();
        fail_closed.on_error = OnError::FailClosed;

        let open_outcome = runner
            .evaluate(&[fail_open], input("hello"))
            .await
            .expect("fail-open evaluation");
        assert!(open_outcome.allowed);
        assert_eq!(open_outcome.body, b"hello");
        assert!(open_outcome.applied[0].failed);

        let closed_outcome = runner
            .evaluate(&[fail_closed], input("hello"))
            .await
            .expect("fail-closed evaluation");
        assert!(!closed_outcome.allowed);
        assert_eq!(
            closed_outcome.reason,
            "middleware_failed: request_body_mode_not_permitted"
        );
        assert!(closed_outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn unspecified_decision_uses_fail_closed() {
        let runner =
            ChainRunner::new_protobuf_for_tests(Arc::new(scripted_service(TestRequestResult {
                decision: Decision::Unspecified as i32,
                ..allow_result()
            })));

        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: missing_preflight_action"
        );
        assert!(outcome.applied[0].failed);
    }

    #[derive(Clone, Default)]
    struct OpenAiRedactionService {
        preflight: Arc<std::sync::Mutex<Option<openshell_core::proto::WebSocketPreflight>>>,
        manifest_name: String,
        describe_calls: Arc<std::sync::atomic::AtomicUsize>,
        skip: bool,
        deny: bool,
        preflight_reason: String,
        preflight_reason_code: String,
        preflight_findings: Vec<Finding>,
        preflight_metadata: HashMap<String, String>,
        close_on_first_message: bool,
        messages: Arc<std::sync::atomic::AtomicUsize>,
        session_ends: Option<
            tokio::sync::mpsc::UnboundedSender<openshell_core::proto::MiddlewareSessionEndReason>,
        >,
    }

    impl OpenAiRedactionService {
        fn websocket_stream<S>(&self, mut requests: S) -> WebSocketResponseStream
        where
            S: Stream<
                    Item = std::result::Result<
                        openshell_core::proto::WebSocketSessionEvent,
                        tonic::Status,
                    >,
                > + Send
                + Unpin
                + 'static,
        {
            use openshell_core::proto::{
                WebSocketMessageResult, WebSocketPreflightAction, WebSocketPreflightDecision,
                WebSocketSessionEventResult, web_socket_message, web_socket_message_result,
                web_socket_session_event, web_socket_session_event_result,
            };

            let preflight = Arc::clone(&self.preflight);
            let skip = self.skip;
            let deny = self.deny;
            let preflight_reason = self.preflight_reason.clone();
            let preflight_reason_code = self.preflight_reason_code.clone();
            let preflight_findings = self.preflight_findings.clone();
            let preflight_metadata = self.preflight_metadata.clone();
            let close_on_first_message = self.close_on_first_message;
            let messages = Arc::clone(&self.messages);
            let session_ends = self.session_ends.clone();
            let (responses_tx, responses_rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(async move {
                while let Some(Ok(request)) = requests.next().await {
                    let response = match request.event {
                        Some(web_socket_session_event::Event::Preflight(value)) => {
                            *preflight.lock().expect("preflight lock") = Some(value);
                            Some(WebSocketSessionEventResult {
                                result: Some(
                                    web_socket_session_event_result::Result::PreflightDecision(
                                        WebSocketPreflightDecision {
                                            action: if deny {
                                                WebSocketPreflightAction::Deny as i32
                                            } else if skip {
                                                WebSocketPreflightAction::Skip as i32
                                            } else {
                                                WebSocketPreflightAction::Inspect as i32
                                            },
                                            reason: preflight_reason.clone(),
                                            findings: preflight_findings.clone(),
                                            metadata: preflight_metadata.clone(),
                                            reason_code: preflight_reason_code.clone(),
                                        },
                                    ),
                                ),
                            })
                        }
                        Some(web_socket_session_event::Event::Message(value)) => {
                            messages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if close_on_first_message {
                                break;
                            }
                            let web_socket_message::Payload::Text(payload) =
                                value.payload.expect("test OpenAI event payload")
                            else {
                                panic!("test OpenAI event must be text");
                            };
                            let payload = payload.replace("customer-secret", "[REDACTED]");
                            Some(WebSocketSessionEventResult {
                                result: Some(
                                    web_socket_session_event_result::Result::MessageResult(
                                        WebSocketMessageResult {
                                            sequence: value.sequence,
                                            decision: Decision::Allow as i32,
                                            replacement: Some(
                                                web_socket_message_result::Replacement::Text(
                                                    payload,
                                                ),
                                            ),
                                            reason_code: "redacted".into(),
                                            ..Default::default()
                                        },
                                    ),
                                ),
                            })
                        }
                        Some(web_socket_session_event::Event::SessionStart(_)) | None => None,
                        Some(web_socket_session_event::Event::SessionEnd(end)) => {
                            if let Some(session_ends) = &session_ends
                                && let Ok(reason) =
                                    openshell_core::proto::MiddlewareSessionEndReason::try_from(
                                        end.reason,
                                    )
                            {
                                let _ = session_ends.send(reason);
                            }
                            None
                        }
                    };
                    if let Some(response) = response
                        && responses_tx.send(Ok(response)).await.is_err()
                    {
                        break;
                    }
                }
            });
            Box::pin(ReceiverStream::new(responses_rx))
        }
    }

    fn websocket_preflight_input(session_id: impl Into<String>) -> WebSocketPreflightInput {
        WebSocketPreflightInput {
            session_id: session_id.into(),
            request_id: "request".into(),
            sandbox_id: "sandbox".into(),
            sandbox_name: "sandbox-name".into(),
            workspace: "wrks-default".into(),
            scheme: "wss".into(),
            host: "api.openai.com".into(),
            port: 443,
            path: "/v1/responses".into(),
            requested_subprotocols: Vec::new(),
        }
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for OpenAiRedactionService {
        type EvaluateWebSocketSessionStream = WebSocketResponseStream;

        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            self.describe_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(tonic::Response::new(MiddlewareManifest {
                name: if self.manifest_name.is_empty() {
                    "test/openai-websocket-redactor".into()
                } else {
                    self.manifest_name.clone()
                },
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: MAX_MIDDLEWARE_PAYLOAD_BYTES as u64,
                    request_timeout: Some(prost_types::Duration {
                        seconds: 1,
                        nanos: 0,
                    }),
                }],
                expected_audience: String::new(),
            }))
        }

        async fn validate_config(
            &self,
            _request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            Ok(tonic::Response::new(ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            }))
        }

        async fn evaluate_web_socket_session(
            &self,
            request: Request<tonic::Streaming<openshell_core::proto::WebSocketSessionEvent>>,
        ) -> std::result::Result<tonic::Response<Self::EvaluateWebSocketSessionStream>, tonic::Status>
        {
            Ok(tonic::Response::new(
                self.websocket_stream(request.into_inner()),
            ))
        }
    }

    #[tonic::async_trait]
    impl SupervisorMiddlewareEndpoint for OpenAiRedactionService {
        async fn describe(
            &self,
            request: Request<()>,
        ) -> std::result::Result<tonic::Response<MiddlewareManifest>, tonic::Status> {
            SupervisorMiddleware::describe(self, request).await
        }

        async fn validate_config(
            &self,
            request: Request<ValidateConfigRequest>,
        ) -> std::result::Result<tonic::Response<ValidateConfigResponse>, tonic::Status> {
            SupervisorMiddleware::validate_config(self, request).await
        }

        async fn open_websocket_session(
            &self,
            receiver: tokio::sync::mpsc::Receiver<openshell_core::proto::WebSocketSessionEvent>,
        ) -> std::result::Result<WebSocketResponseStream, tonic::Status> {
            Ok(self.websocket_stream(ReceiverStream::new(receiver).map(Ok)))
        }
    }

    fn websocket_entry(
        name: &str,
        implementation: &str,
        order: i32,
        on_error: OnError,
    ) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: implementation.into(),
            order,
            config: prost_types::Struct::default(),
            on_error,
        }
    }

    #[tokio::test]
    async fn empty_websocket_chain_skips_describe_and_preflight() {
        let service = OpenAiRedactionService::default();
        let describe_calls = Arc::clone(&service.describe_calls);
        let observed_preflight = Arc::clone(&service.preflight);
        let runner = ChainRunner::from_endpoint(Arc::new(service));

        let outcome = runner
            .preflight_websocket(&[], websocket_preflight_input("empty-chain"))
            .await
            .expect("empty preflight");

        assert!(outcome.allowed);
        assert_eq!(outcome.terminal_reason, None);
        assert!(outcome.session.is_none());
        assert!(outcome.invocations.is_empty());
        assert_eq!(describe_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(observed_preflight.lock().expect("preflight lock").is_none());
    }

    #[tokio::test]
    async fn http_only_attachments_are_reported_but_do_not_select_websocket_stages() {
        for on_error in [OnError::FailClosed, OnError::FailOpen] {
            let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
                manifest_name: "test/http-only".into(),
                max_body_bytes: 4096,
                result: allow_result(),
            }));
            let chain = [ChainEntry {
                name: "http-guard".into(),
                implementation: "test/http-only".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error,
            }];

            let outcome = runner
                .preflight_websocket(
                    &chain,
                    websocket_preflight_input(format!("http-only-{on_error:?}")),
                )
                .await
                .expect("HTTP-only attachment coverage");

            assert!(outcome.allowed);
            assert_eq!(outcome.terminal_reason, None);
            assert!(outcome.session.is_none());
            assert!(outcome.invocations.is_empty());
            assert_eq!(
                outcome.coverage,
                [WebSocketCoverage {
                    config_name: "http-guard".into(),
                    implementation: "test/http-only".into(),
                    state: WebSocketCoverageState::BindingNotSelected,
                    sequence: None,
                    message_type: None,
                    original_size: 0,
                }]
            );
        }
    }

    #[tokio::test]
    async fn http_only_attachment_allows_33_requested_subprotocols() {
        let runner = ChainRunner::new_protobuf_for_tests(Arc::new(ScriptedService {
            manifest_name: "test/http-only".into(),
            max_body_bytes: 4096,
            result: allow_result(),
        }));
        let chain = [ChainEntry {
            name: "http-guard".into(),
            implementation: "test/http-only".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        }];
        let mut input = websocket_preflight_input("http-only-many-subprotocols");
        input.requested_subprotocols = (0..33)
            .map(|index| format!("subprotocol-{index}"))
            .collect();

        let outcome = runner
            .preflight_websocket(&chain, input)
            .await
            .expect("HTTP-only attachment must not validate a WebSocket middleware envelope");

        assert!(outcome.allowed);
        assert_eq!(outcome.terminal_reason, None);
        assert!(outcome.session.is_none());
        assert!(outcome.invocations.is_empty());
        assert_eq!(
            outcome.coverage,
            [WebSocketCoverage {
                config_name: "http-guard".into(),
                implementation: "test/http-only".into(),
                state: WebSocketCoverageState::BindingNotSelected,
                sequence: None,
                message_type: None,
                original_size: 0,
            }]
        );
    }

    #[tokio::test]
    async fn unsupported_binary_messages_advance_sequence_without_applying_on_error() {
        for on_error in [OnError::FailClosed, OnError::FailOpen] {
            let runner = builtin_runner();
            let chain = [entry("regex-redactor", on_error)];
            let preflight = runner
                .preflight_websocket(
                    &chain,
                    websocket_preflight_input(format!("binary-{on_error:?}")),
                )
                .await
                .expect("preflight");
            let mut session = preflight.session.expect("built-in inspects text");
            assert!(session.start("").await.allowed);

            let coverage = session.observe_unsupported_message(WebSocketMessageType::Binary, 23);
            assert_eq!(
                coverage,
                [WebSocketCoverage {
                    config_name: "regex-redactor".into(),
                    implementation: BUILTIN_REGEX.into(),
                    state: WebSocketCoverageState::UnsupportedMessageType,
                    sequence: Some(1),
                    message_type: Some(WebSocketMessageType::Binary),
                    original_size: 23,
                }]
            );

            let text = session.evaluate_text(r#"{"input":"safe"}"#.into()).await;
            assert!(text.allowed);
            assert_eq!(text.invocations[0].sequence, Some(2));
            assert!(!text.invocations[0].failed);

            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
                .await;
        }
    }

    #[tokio::test]
    async fn explicit_websocket_preflight_denial_is_authoritative_for_both_error_modes() {
        use openshell_core::proto::MiddlewareSessionEndReason;

        for on_error in [OnError::FailOpen, OnError::FailClosed] {
            let (session_ends_tx, mut session_ends_rx) = tokio::sync::mpsc::unbounded_channel();
            let runner = ChainRunner::from_endpoint(Arc::new(OpenAiRedactionService {
                deny: true,
                preflight_reason: "contains sensitive request data".into(),
                preflight_reason_code: "upgrade_blocked".into(),
                preflight_findings: vec![Finding {
                    r#type: "content.sensitive".into(),
                    label: "Sensitive content".into(),
                    count: 1,
                    confidence: "high".into(),
                    severity: "high".into(),
                }],
                preflight_metadata: HashMap::from([("policy_version".into(), "1".into())]),
                session_ends: Some(session_ends_tx),
                ..Default::default()
            }));

            let outcome = runner
                .preflight_websocket(
                    &[websocket_entry(
                        "deny-upgrade",
                        "test/openai-websocket-redactor",
                        0,
                        on_error,
                    )],
                    websocket_preflight_input("explicit-denial"),
                )
                .await
                .expect("denied preflight");

            assert!(!outcome.allowed);
            assert_eq!(
                outcome.terminal_reason,
                Some(MiddlewareSessionEndReason::MiddlewareDenial)
            );
            assert_eq!(
                outcome.reason,
                "middleware_denied:deny-upgrade:upgrade_blocked"
            );
            assert_eq!(
                outcome
                    .denial
                    .as_ref()
                    .map(|denial| denial.config_name.as_str()),
                Some("deny-upgrade")
            );
            assert_eq!(
                outcome
                    .denial
                    .as_ref()
                    .and_then(|denial| denial.reason_code.as_deref()),
                Some("upgrade_blocked")
            );
            assert_eq!(
                outcome.invocations[0].reason_code.as_deref(),
                Some("upgrade_blocked")
            );
            assert_eq!(outcome.findings.len(), 1);
            assert_eq!(outcome.findings[0].middleware, "deny-upgrade");
            assert_eq!(outcome.findings[0].finding.r#type, "content.sensitive");
            assert_eq!(outcome.metadata["deny-upgrade"]["policy_version"], "1");
            assert!(!outcome.reason.contains("sensitive request data"));
            assert!(outcome.session.is_none());
            assert_eq!(outcome.invocations.len(), 1);
            assert_eq!(
                outcome.invocations[0].outcome,
                WebSocketInvocationOutcome::Deny
            );
            assert!(!outcome.invocations[0].failed);
            assert_eq!(
                session_ends_rx.recv().await,
                Some(MiddlewareSessionEndReason::MiddlewareDenial)
            );
            assert!(
                session_ends_rx.try_recv().is_err(),
                "each opened stream receives at most one session_end"
            );
        }
    }

    #[tokio::test]
    async fn mixed_websocket_preflight_denial_ends_every_opened_stage() {
        use openshell_core::proto::MiddlewareSessionEndReason;

        let (first_end_tx, mut first_end_rx) = tokio::sync::mpsc::unbounded_channel();
        let (denier_end_tx, mut denier_end_rx) = tokio::sync::mpsc::unbounded_channel();
        let (last_end_tx, mut last_end_rx) = tokio::sync::mpsc::unbounded_channel();
        let endpoints: Vec<Arc<dyn InProcessMiddleware>> = vec![
            in_process_endpoint(Arc::new(OpenAiRedactionService {
                manifest_name: "test/first-inspector".into(),
                session_ends: Some(first_end_tx),
                ..Default::default()
            })),
            in_process_endpoint(Arc::new(OpenAiRedactionService {
                manifest_name: "test/denier".into(),
                deny: true,
                session_ends: Some(denier_end_tx),
                ..Default::default()
            })),
            in_process_endpoint(Arc::new(OpenAiRedactionService {
                manifest_name: "test/last-inspector".into(),
                session_ends: Some(last_end_tx),
                ..Default::default()
            })),
        ];
        let runner = ChainRunner::from_registry(
            MiddlewareRegistry::connect_services(endpoints, Vec::new())
                .await
                .expect("connect mixed middleware services"),
        );
        let chain = [
            websocket_entry("first", "test/first-inspector", 0, OnError::FailClosed),
            websocket_entry("deny", "test/denier", 1, OnError::FailOpen),
            websocket_entry("last", "test/last-inspector", 2, OnError::FailClosed),
        ];

        let outcome = runner
            .preflight_websocket(&chain, websocket_preflight_input("mixed-denial"))
            .await
            .expect("mixed preflight");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.terminal_reason,
            Some(MiddlewareSessionEndReason::MiddlewareDenial)
        );
        assert_eq!(
            outcome
                .invocations
                .iter()
                .map(|invocation| invocation.outcome)
                .collect::<Vec<_>>(),
            vec![
                WebSocketInvocationOutcome::Inspect,
                WebSocketInvocationOutcome::Deny,
                WebSocketInvocationOutcome::Inspect,
            ]
        );
        for receiver in [&mut first_end_rx, &mut denier_end_rx, &mut last_end_rx] {
            assert_eq!(
                receiver.recv().await,
                Some(MiddlewareSessionEndReason::MiddlewareDenial)
            );
            assert!(
                receiver.try_recv().is_err(),
                "each opened stream receives at most one session_end"
            );
        }
        assert_eq!(
            runner.registry.session_admission.available_permits(),
            MAX_CONCURRENT_MIDDLEWARE_SESSIONS
        );
    }

    #[tokio::test]
    async fn builtin_regex_redacts_ordered_websocket_text_messages() {
        let runner = builtin_runner();
        let chain = [entry("regex-redactor", OnError::FailClosed)];
        let preflight = runner
            .preflight_websocket(
                &chain,
                WebSocketPreflightInput {
                    session_id: "builtin-regex-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: vec!["realtime".into()],
                },
            )
            .await
            .expect("preflight");
        assert!(preflight.allowed);
        assert_eq!(
            preflight.invocations[0].outcome,
            WebSocketInvocationOutcome::Inspect
        );
        let mut session = preflight.session.expect("built-in chose to inspect");
        assert!(session.start("realtime").await.allowed);

        let original = r#"{"type":"response.create","response":{"input":"sk-ABCDEFGHIJKLMNOP"}}"#;
        let redacted = session.evaluate_text(original.into()).await;
        assert!(redacted.allowed);
        assert_eq!(
            redacted.payload,
            r#"{"type":"response.create","response":{"input":"[REDACTED]"}}"#
        );
        assert_eq!(redacted.invocations[0].sequence, Some(1));
        assert!(redacted.invocations[0].transformed);
        assert_eq!(redacted.findings.len(), 1);
        assert_eq!(redacted.findings[0].middleware, "regex-redactor");
        assert_eq!(redacted.findings[0].finding.r#type, "regex.openai");
        assert_eq!(
            redacted.metadata["regex-redactor"]["regex_matches_replaced"],
            "1"
        );

        let unchanged = session
            .evaluate_text(r#"{"type":"response.cancel"}"#.into())
            .await;
        assert!(unchanged.allowed);
        assert_eq!(unchanged.payload, r#"{"type":"response.cancel"}"#);
        assert_eq!(unchanged.invocations[0].sequence, Some(2));
        assert!(!unchanged.invocations[0].transformed);
        assert!(unchanged.findings.is_empty());
        assert!(unchanged.metadata.is_empty());

        let oversized = session.evaluate_text("a".repeat(256 * 1024 + 1)).await;
        assert!(!oversized.allowed);
        assert_eq!(
            oversized.reason,
            "middleware_failed: request_message_over_capacity"
        );
        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
    }

    #[tokio::test]
    async fn builtin_regex_redacts_after_fail_open_message_capacity_gap() {
        let runner = builtin_runner();
        let chain = [entry("regex-redactor", OnError::FailOpen)];
        let preflight = runner
            .preflight_websocket(
                &chain,
                WebSocketPreflightInput {
                    session_id: "builtin-regex-gap-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: vec!["realtime".into()],
                },
            )
            .await
            .expect("preflight");
        assert!(preflight.allowed);
        let mut session = preflight.session.expect("built-in chose to inspect");
        assert!(session.start("realtime").await.allowed);

        let oversized_payload = "a".repeat(256 * 1024 + 1);
        let oversized = session.evaluate_text(oversized_payload.clone()).await;
        assert!(oversized.allowed);
        assert_eq!(oversized.payload, oversized_payload);
        assert_eq!(oversized.invocations[0].sequence, Some(1));
        assert_eq!(
            oversized.invocations[0].outcome,
            WebSocketInvocationOutcome::FailOpen
        );
        assert!(!oversized.invocations[0].stage_disabled);

        let original = r#"{"type":"response.create","response":{"input":"sk-ABCDEFGHIJKLMNOP"}}"#;
        let redacted = session.evaluate_text(original.into()).await;
        assert!(redacted.allowed);
        assert_eq!(
            redacted.payload,
            r#"{"type":"response.create","response":{"input":"[REDACTED]"}}"#
        );
        assert_eq!(redacted.invocations[0].sequence, Some(2));
        assert_eq!(
            redacted.invocations[0].outcome,
            WebSocketInvocationOutcome::Allow
        );
        assert!(redacted.invocations[0].transformed);
        assert!(!redacted.invocations[0].stage_disabled);

        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
    }

    #[tokio::test]
    async fn in_process_websocket_endpoint_redacts_openai_event() {
        let service = OpenAiRedactionService::default();
        let runner = ChainRunner::from_endpoint(Arc::new(service));
        let chain = [ChainEntry {
            name: "openai-redactor".into(),
            implementation: "test/openai-websocket-redactor".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        }];
        let preflight = runner
            .preflight_websocket(
                &chain,
                WebSocketPreflightInput {
                    session_id: "in-process-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: vec!["realtime".into()],
                },
            )
            .await
            .expect("preflight");
        assert!(preflight.allowed);
        let mut session = preflight.session.expect("middleware chose to inspect");
        assert!(session.start("realtime").await.allowed);

        let original = r#"{"type":"response.create","response":{"input":"customer-secret"}}"#;
        let outcome = session.evaluate_text(original.into()).await;
        assert!(outcome.allowed);
        assert_eq!(
            outcome.payload,
            r#"{"type":"response.create","response":{"input":"[REDACTED]"}}"#
        );
        assert!(outcome.invocations[0].transformed);
        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
    }

    #[tokio::test]
    async fn openai_websocket_event_is_introspected_and_redacted() {
        let service = OpenAiRedactionService::default();
        let observed_preflight = Arc::clone(&service.preflight);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let registry = MiddlewareRegistry::connect_services(Vec::new(), vec![registration])
            .await
            .expect("connect WebSocket middleware");
        let runner = ChainRunner::from_registry(registry);
        let chain = [ChainEntry {
            name: "openai-redactor".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        }];
        let described = runner
            .describe_websocket_chain(&chain)
            .await
            .expect("describe WebSocket chain");
        assert_eq!(
            described[0].max_payload_bytes(),
            1024,
            "operator max_payload_bytes must cap WebSocket messages"
        );
        let preflight = runner
            .preflight_websocket(
                &chain,
                WebSocketPreflightInput {
                    session_id: "ws-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: vec!["realtime".into()],
                },
            )
            .await
            .expect("preflight");
        assert!(preflight.allowed);
        let mut session = preflight.session.expect("middleware chose to inspect");
        assert!(session.start("realtime").await.allowed);

        let original = r#"{"type":"response.create","response":{"input":"customer-secret"}}"#;
        let outcome = session.evaluate_text(original.into()).await;
        assert!(outcome.allowed);
        let transformed = outcome.payload;
        assert!(transformed.contains("[REDACTED]"));
        assert!(!transformed.contains("customer-secret"));
        assert!(outcome.invocations[0].transformed);

        let observed = observed_preflight
            .lock()
            .expect("preflight lock")
            .clone()
            .expect("preflight observed");
        let target = observed.target.expect("preflight target");
        assert_eq!(target.scheme, "wss");
        assert_eq!(target.host, "api.openai.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.method, "GET");
        assert_eq!(target.path, "/v1/responses");
        assert!(target.query.is_empty());
        assert_eq!(observed.requested_subprotocols, ["realtime"]);
        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve middleware");
    }

    #[tokio::test]
    async fn fail_open_disables_broken_websocket_stage_for_later_messages() {
        let service = OpenAiRedactionService {
            close_on_first_message: true,
            ..Default::default()
        };
        let observed_preflight = Arc::clone(&service.preflight);
        let message_count = Arc::clone(&service.messages);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);

        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let registry = MiddlewareRegistry::connect_services(Vec::new(), vec![registration])
            .await
            .expect("connect WebSocket middleware");
        let runner = ChainRunner::from_registry(registry);
        let chain = [ChainEntry {
            name: "openai-redactor".into(),
            implementation: "local-guard-service".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        }];
        let preflight = runner
            .preflight_websocket(
                &chain,
                WebSocketPreflightInput {
                    session_id: "ws-session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "ws".into(),
                    host: "api.openai.com".into(),
                    port: 80,
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");
        let mut session = preflight.session.expect("middleware chose to inspect");
        assert!(session.start("").await.allowed);
        assert_eq!(
            observed_preflight
                .lock()
                .expect("preflight lock")
                .as_ref()
                .expect("preflight observed")
                .target
                .as_ref()
                .expect("preflight target")
                .scheme,
            "ws"
        );

        let first = session
            .evaluate_text(r#"{"type":"response.create"}"#.into())
            .await;
        assert!(first.allowed, "fail-open should bypass the broken stage");
        assert_eq!(first.invocations.len(), 1);
        assert!(first.invocations[0].failed);
        assert!(first.invocations[0].stage_disabled);
        assert_eq!(
            runner.registry.session_admission.available_permits(),
            MAX_CONCURRENT_MIDDLEWARE_SESSIONS,
            "the final disabled stage must release persistent session capacity"
        );

        let mut work = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
            work.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("fill middleware work budget"),
            );
        }

        let second = session
            .evaluate_text(r#"{"type":"response.cancel"}"#.into())
            .now_or_never()
            .expect("fully disabled session must bypass without waiting for work admission");
        assert!(second.allowed);
        assert!(
            second.invocations.is_empty(),
            "disabled stage must not be called again in this session"
        );
        assert_eq!(message_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(work);

        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join test middleware")
            .expect("serve middleware");
    }

    #[tokio::test]
    async fn mixed_websocket_session_keeps_message_admission_while_one_stage_is_active() {
        let broken = Arc::new(OpenAiRedactionService {
            close_on_first_message: true,
            ..Default::default()
        });
        let mut endpoints = services();
        endpoints.push(in_process_endpoint(broken));
        let runner = ChainRunner::from_registry(
            MiddlewareRegistry::connect_services(endpoints, Vec::new())
                .await
                .expect("connect mixed middleware services"),
        );
        let broken_entry = ChainEntry {
            name: "best-effort-remote".into(),
            implementation: "test/openai-websocket-redactor".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let mut regex_entry = entry("required-regex", OnError::FailClosed);
        regex_entry.order = 1;
        let preflight = runner
            .preflight_websocket(
                &[broken_entry, regex_entry],
                websocket_preflight_input("mixed-active"),
            )
            .await
            .expect("mixed preflight");
        let mut session = preflight.session.expect("both stages inspect");
        assert!(session.start("").await.allowed);

        let first = session
            .evaluate_text(r#"{"input":"sk-ABCDEFGHIJKLMNOP"}"#.into())
            .await;
        assert!(first.allowed);
        assert!(first.invocations[0].stage_disabled);
        assert_eq!(
            first.invocations[1].outcome,
            WebSocketInvocationOutcome::Allow
        );

        let mut work = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
            work.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("fill middleware work budget"),
            );
        }
        assert!(
            session.admit_message().now_or_never().is_none(),
            "an active remaining stage must still wait for message work admission"
        );
        drop(work);

        let second = session
            .evaluate_text(r#"{"input":"sk-QRSTUVWXYZabcdef"}"#.into())
            .await;
        assert!(second.allowed);
        assert_eq!(second.invocations.len(), 1);
        assert_eq!(
            second.invocations[0].config_name, "required-regex",
            "disabled stage must stay bypassed while the active stage continues"
        );
    }

    #[tokio::test]
    async fn websocket_admission_wait_queue_is_bounded() {
        let runner = ChainRunner::default();
        let mut active = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
            active.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("active admission"),
            );
        }

        let mut waiters = Vec::new();
        for _ in 0..MAX_QUEUED_MIDDLEWARE_WORK {
            let runner = runner.clone();
            waiters.push(tokio::spawn(async move {
                runner.reserve_middleware_work().await
            }));
        }
        while runner.registry.work_admission_waiters.available_permits() != 0 {
            tokio::task::yield_now().await;
        }

        let overflow = runner
            .reserve_middleware_work()
            .await
            .expect("admission outcome");
        assert!(matches!(
            overflow,
            MiddlewareWorkAdmissionOutcome::QueueExhausted
        ));
        runner
            .reserve_middleware_work_admission()
            .await
            .expect_err("WebSocket callers retain their existing failure path");

        drop(active);
        for waiter in waiters {
            let admission = waiter
                .await
                .expect("waiter task")
                .expect("queued admission after capacity is released");
            assert!(matches!(
                admission,
                MiddlewareWorkAdmissionOutcome::Admitted(_)
            ));
        }
        assert_eq!(
            runner.registry.work_admission.available_permits(),
            MAX_CONCURRENT_MIDDLEWARE_WORK
        );
        assert_eq!(
            runner.registry.work_admission_waiters.available_permits(),
            MAX_QUEUED_MIDDLEWARE_WORK
        );

        let mut recovered = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
            recovered.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("recovered active admission"),
            );
        }
        assert_eq!(recovered.len(), MAX_CONCURRENT_MIDDLEWARE_WORK);
    }

    #[tokio::test]
    async fn websocket_queue_exhaustion_remains_a_protocol_failure() {
        let runner = builtin_runner();
        let chain = [entry("regex-redactor", OnError::FailClosed)];
        let preflight = runner
            .preflight_websocket(&chain, websocket_preflight_input("established"))
            .await
            .expect("initial preflight");
        let mut session = preflight.session.expect("built-in inspects session");
        assert!(session.start("").await.allowed);

        let mut active = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_WORK {
            active.push(
                runner
                    .reserve_middleware_work_admission()
                    .await
                    .expect("fill active work"),
            );
        }
        let mut waiters = Vec::new();
        for _ in 0..MAX_QUEUED_MIDDLEWARE_WORK {
            let runner = runner.clone();
            waiters.push(tokio::spawn(async move {
                runner.reserve_middleware_work().await
            }));
        }
        while runner.registry.work_admission_waiters.available_permits() != 0 {
            tokio::task::yield_now().await;
        }

        let preflight_overflow = runner
            .preflight_websocket(&chain, websocket_preflight_input("preflight-overflow"))
            .await;
        assert!(
            preflight_overflow.is_err(),
            "preflight exhaustion remains an outer HTTP failure"
        );
        session
            .admit_message()
            .await
            .expect_err("established message exhaustion remains a typed termination input");

        for waiter in waiters {
            waiter.abort();
        }
        drop(active);
    }

    #[tokio::test]
    async fn websocket_preflight_skip_removes_stage_without_message_calls() {
        let (session_ends_tx, mut session_ends_rx) = tokio::sync::mpsc::unbounded_channel();
        let service = OpenAiRedactionService {
            skip: true,
            session_ends: Some(session_ends_tx),
            ..Default::default()
        };
        let message_count = Arc::clone(&service.messages);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind WebSocket middleware");
        let address = listener.local_addr().expect("middleware address");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tonic::transport::Server::builder()
            .add_service(SupervisorMiddlewareServer::new(service))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = shutdown_rx.await;
            });
        let server_task = tokio::spawn(server);
        let mut registration = external_registration(1024);
        registration.grpc_endpoint = format!("http://{address}");
        let runner = ChainRunner::from_registry(
            MiddlewareRegistry::connect_services(Vec::new(), vec![registration])
                .await
                .expect("connect middleware"),
        );
        let result = runner
            .preflight_websocket(
                &[ChainEntry {
                    name: "scope".into(),
                    implementation: "local-guard-service".into(),
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: OnError::FailClosed,
                }],
                WebSocketPreflightInput {
                    session_id: "session".into(),
                    request_id: "request".into(),
                    sandbox_id: "sandbox".into(),
                    sandbox_name: "sandbox-name".into(),
                    workspace: "wrks-default".into(),
                    scheme: "wss".into(),
                    host: "api.openai.com".into(),
                    port: 443,
                    path: "/v1/responses".into(),
                    requested_subprotocols: Vec::new(),
                },
            )
            .await
            .expect("preflight");
        assert!(result.allowed);
        assert!(result.session.is_none());
        assert_eq!(
            result.invocations[0].outcome,
            WebSocketInvocationOutcome::Skip
        );
        assert_eq!(message_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            runner.registry.session_admission.available_permits(),
            MAX_CONCURRENT_MIDDLEWARE_SESSIONS,
            "all-skip preflight must not retain session capacity"
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), session_ends_rx.recv())
                .await
                .expect("skipped stage must receive session_end"),
            Some(openshell_core::proto::MiddlewareSessionEndReason::StageSkipped)
        );
        assert!(
            session_ends_rx.try_recv().is_err(),
            "a skipped stage receives at most one session_end"
        );
        let _ = shutdown_tx.send(());
        server_task
            .await
            .expect("join middleware")
            .expect("serve middleware");
    }

    #[tokio::test]
    async fn websocket_session_budget_caps_idle_inspecting_sessions_and_releases_on_end() {
        let runner = builtin_runner();
        let chain = [entry("regex-redactor", OnError::FailClosed)];
        let mut sessions = Vec::new();
        for index in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
            let preflight = runner
                .preflight_websocket(
                    &chain,
                    websocket_preflight_input(format!("session-{index}")),
                )
                .await
                .expect("admit inspecting session");
            assert!(preflight.allowed);
            sessions.push(preflight.session.expect("built-in inspects session"));
        }
        assert_eq!(runner.registry.session_admission.available_permits(), 0);

        let overflow = runner
            .preflight_websocket(&chain, websocket_preflight_input("overflow"))
            .await
            .expect("capacity exhaustion is a typed preflight outcome");
        assert!(!overflow.allowed);
        assert!(overflow.session.is_none());
        assert!(overflow.session_capacity_exhausted);
        assert_eq!(
            overflow.invocations[0].outcome,
            WebSocketInvocationOutcome::FailClosed
        );

        sessions
            .pop()
            .expect("retained session")
            .end(openshell_core::proto::MiddlewareSessionEndReason::Normal)
            .await;
        assert_eq!(runner.registry.session_admission.available_permits(), 1);

        let replacement = runner
            .preflight_websocket(&chain, websocket_preflight_input("replacement"))
            .await
            .expect("released session capacity is reusable");
        assert!(replacement.allowed);
        assert!(replacement.session.is_some());
    }

    #[tokio::test]
    async fn websocket_session_budget_survives_registry_replacement() {
        let runner = builtin_runner();
        let chain = [entry("regex-redactor", OnError::FailClosed)];
        let mut sessions = Vec::new();
        for index in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
            let preflight = runner
                .preflight_websocket(
                    &chain,
                    websocket_preflight_input(format!("old-generation-{index}")),
                )
                .await
                .expect("admit old-generation session");
            sessions.push(preflight.session.expect("built-in inspects session"));
        }

        let replacement_registry = MiddlewareRegistry::connect_services(services(), Vec::new())
            .await
            .expect("connect replacement registry");
        let replacement = runner.with_replacement_registry(replacement_registry);
        let overflow = replacement
            .preflight_websocket(&chain, websocket_preflight_input("new-generation-overflow"))
            .await
            .expect("capacity exhaustion is a typed preflight outcome");
        assert!(!overflow.allowed);
        assert!(overflow.session_capacity_exhausted);

        sessions
            .pop()
            .expect("retained old-generation session")
            .end(openshell_core::proto::MiddlewareSessionEndReason::PolicyReload)
            .await;
        let admitted = replacement
            .preflight_websocket(&chain, websocket_preflight_input("new-generation-admitted"))
            .await
            .expect("released capacity is reusable after replacement");
        assert!(admitted.allowed);
        assert!(admitted.session.is_some());
    }

    #[tokio::test]
    async fn websocket_session_capacity_exhaustion_honors_mixed_on_error() {
        let runner = builtin_runner();
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_MIDDLEWARE_SESSIONS {
            match runner.try_reserve_middleware_session() {
                MiddlewareSessionAdmission::Admitted(admission) => held.push(admission),
                MiddlewareSessionAdmission::AtCapacity => {
                    panic!("session budget exhausted before platform limit")
                }
            }
        }

        let mut first = entry("best-effort-a", OnError::FailOpen);
        first.order = 1;
        let mut second = entry("best-effort-b", OnError::FailOpen);
        second.order = 2;
        let all_fail_open = runner
            .preflight_websocket(
                &[first.clone(), second.clone()],
                websocket_preflight_input("all-fail-open"),
            )
            .await
            .expect("all-fail-open capacity outcome");
        assert!(all_fail_open.allowed);
        assert!(all_fail_open.session.is_none());
        assert!(all_fail_open.session_capacity_exhausted);
        assert!(
            all_fail_open
                .invocations
                .iter()
                .all(|invocation| invocation.outcome == WebSocketInvocationOutcome::FailOpen)
        );

        second.on_error = OnError::FailClosed;
        let mixed = runner
            .preflight_websocket(&[first, second], websocket_preflight_input("mixed"))
            .await
            .expect("mixed capacity outcome");
        assert!(!mixed.allowed);
        assert!(mixed.session.is_none());
        assert!(mixed.session_capacity_exhausted);
        assert_eq!(
            mixed
                .invocations
                .iter()
                .map(|invocation| invocation.outcome)
                .collect::<Vec<_>>(),
            [
                WebSocketInvocationOutcome::FailOpen,
                WebSocketInvocationOutcome::FailClosed,
            ]
        );
        drop(held);
    }
}
