// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod signer;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use openshell_core::middleware::{HttpRequestResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_request_pre_credentials_server::{
    HttpRequestPreCredentials, HttpRequestPreCredentialsServer,
};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Finding, HttpRequestBodyFinalize, HttpRequestBodyMode, HttpRequestBodyOutput,
    HttpRequestBodyResult, HttpRequestBodyTakeOwnership, HttpRequestEvent, HttpRequestEventResult,
    HttpRequestPreflight, HttpRequestPreflightInspect, HttpRequestPreflightResult,
    HttpRequestPreflightSkip, HttpRequestTrailersResult, MiddlewareBinding, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketSessionEvent, http_request_body_result,
    http_request_body_unit, http_request_event, http_request_event_result,
    http_request_preflight_result,
};
use openshell_extension_core::{
    EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims, MAX_EXTENSION_TOKEN_TTL,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::signer::{GitSigner, SignControl};

const MANIFEST_NAME: &str = "example/git-commit-signing";
const OPERATION: SupervisorMiddlewareOperation = SupervisorMiddlewareOperation::HttpRequest;
const PHASE: SupervisorMiddlewarePhase = SupervisorMiddlewarePhase::PreCredentials;
const MAX_UNIT_BYTES: usize = 64 * 1024;
const JWT_CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Parser)]
#[command(about = "Sign commits in Git smart-HTTP pushes outside an OpenShell sandbox")]
struct Cli {
    /// Address on which to serve authenticated TLS gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,

    /// Local SSH private key used by ssh-keygen. This path is never sent to the sandbox.
    #[arg(long)]
    signing_key: PathBuf,

    /// PEM certificate presented by this middleware service.
    #[arg(long)]
    tls_cert: PathBuf,

    /// PEM private key for the middleware TLS certificate.
    #[arg(long)]
    tls_key: PathBuf,

    /// PEM Ed25519 public key used to verify OpenShell extension JWTs.
    #[arg(long)]
    extension_public_key: PathBuf,

    /// Gateway ID expected in extension-token issuer claims.
    #[arg(long)]
    expected_gateway_id: String,

    /// Exact extension JWT audience configured for this registration.
    #[arg(long)]
    audience: String,

    /// Maximum number of concurrent Git rewrite workers.
    #[arg(long, default_value_t = 2)]
    max_concurrent_signings: usize,

    /// Total deadline for fetch, rewrite, signing, and pack generation.
    #[arg(long, default_value_t = 25)]
    signing_timeout_seconds: u64,
}

struct ExtensionAuth {
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl ExtensionAuth {
    fn new(public_key_pem: &[u8], gateway_id: &str, audience: String) -> Result<Self, String> {
        if gateway_id.is_empty() || audience.is_empty() {
            return Err("expected gateway ID and audience must be nonempty".into());
        }
        let decoding_key = DecodingKey::from_ed_pem(public_key_pem)
            .map_err(|error| format!("invalid extension public key: {error}"))?;
        Ok(Self {
            decoding_key,
            issuer: format!("openshell-gateway:{gateway_id}"),
            audience,
        })
    }

    fn authenticate<T>(
        &self,
        request: &Request<T>,
        required_caller: Option<ExtensionCallerKind>,
    ) -> Result<(), Status> {
        let authorization = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("extension bearer token is required"))?;
        let header = decode_header(authorization)
            .map_err(|_| Status::unauthenticated("extension bearer token is invalid"))?;
        if header.alg != Algorithm::EdDSA
            || header.typ.as_deref() != Some(EXTENSION_JWT_TYP)
            || header.kid.as_deref().is_none_or(str::is_empty)
        {
            return Err(Status::unauthenticated(
                "extension bearer token header is invalid",
            ));
        }
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "iat", "exp", "jti"]);
        let claims = decode::<ExtensionJwtClaims>(authorization, &self.decoding_key, &validation)
            .map_err(|_| Status::unauthenticated("extension bearer token is invalid"))?
            .claims;
        if claims.jti.is_empty()
            || claims.iat < 0
            || claims.exp <= claims.iat
            || u64::try_from(claims.exp - claims.iat)
                .ok()
                .is_none_or(|ttl| ttl > MAX_EXTENSION_TOKEN_TTL.as_secs())
        {
            return Err(Status::unauthenticated(
                "extension bearer token lifetime is invalid",
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Status::internal("system clock is before the Unix epoch"))?
            .as_secs() as i64;
        if claims.iat > now.saturating_add(JWT_CLOCK_SKEW_SECONDS) {
            return Err(Status::unauthenticated(
                "extension bearer token issue time is invalid",
            ));
        }
        if required_caller.is_some_and(|required| claims.caller_kind != required) {
            return Err(Status::permission_denied(
                "extension caller kind is not authorized for this RPC",
            ));
        }
        match claims.caller_kind {
            ExtensionCallerKind::Gateway
                if claims.sandbox_id.is_none() && claims.sub == self.issuer => {}
            ExtensionCallerKind::Supervisor => {
                let sandbox_id = claims.sandbox_id.as_deref().filter(|id| !id.is_empty());
                if sandbox_id
                    .is_none_or(|id| claims.sub != format!("spiffe://openshell/sandbox/{id}"))
                {
                    return Err(Status::permission_denied(
                        "extension supervisor identity is invalid",
                    ));
                }
            }
            _ => {
                return Err(Status::permission_denied(
                    "extension gateway identity is invalid",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct GitSigningMiddleware {
    signer: Arc<GitSigner>,
    auth: Arc<ExtensionAuth>,
    signing_slots: Arc<tokio::sync::Semaphore>,
    signing_timeout: Duration,
    expected_audience: String,
}

impl GitSigningMiddleware {
    fn new(
        signing_key: PathBuf,
        max_concurrent_signings: usize,
        signing_timeout: Duration,
        auth: ExtensionAuth,
    ) -> Result<Self, String> {
        if max_concurrent_signings == 0 {
            return Err("max concurrent signings must be positive".into());
        }
        Ok(Self {
            signer: Arc::new(GitSigner::new(signing_key)?),
            expected_audience: auth.audience.clone(),
            auth: Arc::new(auth),
            signing_slots: Arc::new(tokio::sync::Semaphore::new(max_concurrent_signings)),
            signing_timeout,
        })
    }

    #[cfg(test)]
    fn new_for_test(signing_key: PathBuf) -> Result<Self, String> {
        Ok(Self {
            signer: Arc::new(GitSigner::new(signing_key)?),
            auth: Arc::new(ExtensionAuth {
                decoding_key: DecodingKey::from_secret(b"unused-test-key"),
                issuer: "openshell-gateway:test".into(),
                audience: "urn:openshell:extension:test:git-signing".into(),
            }),
            signing_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            signing_timeout: Duration::from_secs(60),
            expected_audience: "urn:openshell:extension:test:git-signing".into(),
        })
    }

    fn request_stream<S>(&self, mut events: S) -> HttpRequestResultStream
    where
        S: tokio_stream::Stream<Item = Result<HttpRequestEvent, Status>> + Send + Unpin + 'static,
    {
        let signer = Arc::clone(&self.signer);
        let signing_slots = Arc::clone(&self.signing_slots);
        let signing_timeout = self.signing_timeout;
        let (results_tx, results_rx) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let mut selection = None;
            let mut input = None;
            let mut input_bytes = 0u64;
            let mut next_input_sequence = 1u64;
            let mut final_input_sequence = None;

            while let Some(event) = events.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = results_tx.send(Err(error)).await;
                        break;
                    }
                };
                match event.event {
                    Some(http_request_event::Event::Preflight(preflight))
                        if selection.is_none() =>
                    {
                        match select_request(&preflight) {
                            Ok(None) => {
                                selection = Some(Selection::Skipped);
                                if results_tx.send(Ok(preflight_skip())).await.is_err() {
                                    break;
                                }
                            }
                            Ok(Some(selected)) => {
                                if !preflight
                                    .permitted_body_modes
                                    .contains(&(HttpRequestBodyMode::OwnedStreamBytes as i32))
                                    || preflight.max_deferred_bytes == 0
                                {
                                    send_stream_error(
                                        &results_tx,
                                        Status::failed_precondition(
                                            "Git signing requires fail-closed owned request streaming",
                                        ),
                                    )
                                    .await;
                                    break;
                                }
                                match tempfile::tempfile() {
                                    Ok(file) => {
                                        input = Some(tokio::fs::File::from_std(file));
                                        selection = Some(selected);
                                        if results_tx.send(Ok(preflight_owned())).await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(_) => {
                                        send_stream_error(
                                            &results_tx,
                                            Status::resource_exhausted(
                                                "Git signing temporary storage is unavailable",
                                            ),
                                        )
                                        .await;
                                        break;
                                    }
                                }
                            }
                            Err(status) => {
                                send_stream_error(&results_tx, status).await;
                                break;
                            }
                        }
                    }
                    Some(http_request_event::Event::Body(body))
                        if matches!(selection, Some(Selection::Sign { .. }))
                            && final_input_sequence.is_none() =>
                    {
                        if body.sequence != next_input_sequence {
                            send_stream_error(
                                &results_tx,
                                Status::invalid_argument(
                                    "Git signing input sequence is not contiguous",
                                ),
                            )
                            .await;
                            break;
                        }
                        let Some(http_request_body_unit::Payload::Data(data)) = body.payload else {
                            send_stream_error(
                                &results_tx,
                                Status::invalid_argument("Git signing body data is required"),
                            )
                            .await;
                            break;
                        };
                        input_bytes = input_bytes.saturating_add(data.len() as u64);
                        let max_deferred_bytes = match selection.as_ref() {
                            Some(Selection::Sign { limits, .. }) => limits.deferred_bytes,
                            _ => 0,
                        };
                        if input_bytes > max_deferred_bytes {
                            send_stream_error(
                                &results_tx,
                                Status::resource_exhausted(
                                    "Git signing request exceeds deferred storage limit",
                                ),
                            )
                            .await;
                            break;
                        }
                        let Some(file) = input.as_mut() else {
                            send_stream_error(
                                &results_tx,
                                Status::internal("Git signing temporary storage was lost"),
                            )
                            .await;
                            break;
                        };
                        if file.write_all(&data).await.is_err() {
                            send_stream_error(
                                &results_tx,
                                Status::resource_exhausted(
                                    "Git signing temporary storage write failed",
                                ),
                            )
                            .await;
                            break;
                        }
                        if results_tx
                            .send(Ok(body_take_ownership(body.sequence)))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        next_input_sequence = next_input_sequence.saturating_add(1);
                        if body.end_of_stream {
                            final_input_sequence = Some(body.sequence);
                            let Some(Selection::Sign {
                                upstream_url,
                                request_id,
                                limits,
                                ..
                            }) = selection.as_ref()
                            else {
                                break;
                            };
                            let upstream_url = upstream_url.clone();
                            let request_id = request_id.clone();
                            let limits = *limits;
                            if let Err(error) = finish_signing(
                                Arc::clone(&signer),
                                SigningRequest {
                                    input: input
                                        .take()
                                        .expect("selected request has temporary storage"),
                                    upstream_url,
                                    request_id,
                                    final_input_sequence: body.sequence,
                                    limits,
                                },
                                Arc::clone(&signing_slots),
                                signing_timeout,
                                &results_tx,
                            )
                            .await
                            {
                                send_stream_error(&results_tx, error).await;
                                break;
                            }
                        }
                    }
                    Some(http_request_event::Event::Trailers(_))
                        if final_input_sequence.is_some() =>
                    {
                        if results_tx
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
                    Some(http_request_event::Event::SessionEnd(_)) if selection.is_some() => break,
                    _ => {
                        send_stream_error(
                            &results_tx,
                            Status::failed_precondition(
                                "invalid Git signing request stream lifecycle",
                            ),
                        )
                        .await;
                        break;
                    }
                }
            }
        });
        Box::pin(ReceiverStream::new(results_rx))
    }
}

enum Selection {
    Skipped,
    Sign {
        upstream_url: String,
        request_id: String,
        limits: OwnedOutputLimits,
    },
}

#[derive(Clone, Copy)]
struct OwnedOutputLimits {
    deferred_bytes: u64,
    unit_bytes: usize,
}

struct SigningRequest {
    input: tokio::fs::File,
    upstream_url: String,
    request_id: String,
    final_input_sequence: u64,
    limits: OwnedOutputLimits,
}

#[tonic::async_trait]
impl SupervisorMiddleware for GitSigningMiddleware {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(&self, request: Request<()>) -> Result<Response<MiddlewareManifest>, Status> {
        self.auth.authenticate(&request, None)?;
        Ok(Response::new(MiddlewareManifest {
            name: MANIFEST_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                operation: OPERATION as i32,
                phase: PHASE as i32,
                max_payload_bytes: MAX_UNIT_BYTES as u64,
                request_timeout: Some(prost_types::Duration {
                    seconds: 30,
                    nanos: 0,
                }),
            }],
            expected_audience: self.expected_audience.clone(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Gateway))?;
        let request = request.into_inner();
        let unknown = request
            .config
            .as_ref()
            .and_then(|config| config.fields.keys().next())
            .cloned();
        Ok(Response::new(match unknown {
            None => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Some(field) => ValidateConfigResponse {
                valid: false,
                reason: format!("unsupported config field '{field}'"),
            },
        }))
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Supervisor))?;
        Err(Status::unimplemented(
            "WebSocket middleware is not supported",
        ))
    }
}

#[tonic::async_trait]
impl HttpRequestPreCredentials for GitSigningMiddleware {
    type EvaluateStream = HttpRequestResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpRequestEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        self.auth
            .authenticate(&request, Some(ExtensionCallerKind::Supervisor))?;
        Ok(Response::new(self.request_stream(request.into_inner())))
    }
}

fn select_request(preflight: &HttpRequestPreflight) -> Result<Option<Selection>, Status> {
    if !is_receive_pack_request(preflight) {
        return Ok(None);
    }
    let target = preflight
        .target
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Git push request has no target"))?;
    let max_output_unit_bytes = usize::try_from(preflight.max_payload_bytes)
        .ok()
        .filter(|limit| *limit > 0)
        .map(|limit| limit.min(MAX_UNIT_BYTES))
        .ok_or_else(|| Status::failed_precondition("Git signing output unit limit is invalid"))?;
    Ok(Some(Selection::Sign {
        upstream_url: github_upstream_url(target)?,
        request_id: preflight
            .context
            .as_ref()
            .map(|context| context.request_id.clone())
            .unwrap_or_default(),
        limits: OwnedOutputLimits {
            deferred_bytes: preflight.max_deferred_bytes,
            unit_bytes: max_output_unit_bytes,
        },
    }))
}

fn preflight_skip() -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::PreflightResult(
            HttpRequestPreflightResult {
                action: Some(http_request_preflight_result::Action::Skip(
                    HttpRequestPreflightSkip {},
                )),
                reason_code: "not_git_receive_pack".into(),
                ..Default::default()
            },
        )),
    }
}

fn preflight_owned() -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::PreflightResult(
            HttpRequestPreflightResult {
                action: Some(http_request_preflight_result::Action::Inspect(
                    HttpRequestPreflightInspect {
                        body_mode: HttpRequestBodyMode::OwnedStreamBytes as i32,
                        header_mutations: Vec::new(),
                    },
                )),
                reason_code: "git_receive_pack_selected".into(),
                ..Default::default()
            },
        )),
    }
}

fn body_take_ownership(sequence: u64) -> HttpRequestEventResult {
    HttpRequestEventResult {
        result: Some(http_request_event_result::Result::BodyResult(
            HttpRequestBodyResult {
                sequence,
                action: Some(http_request_body_result::Action::TakeOwnership(
                    HttpRequestBodyTakeOwnership {},
                )),
                ..Default::default()
            },
        )),
    }
}

async fn finish_signing(
    signer: Arc<GitSigner>,
    request: SigningRequest,
    signing_slots: Arc<tokio::sync::Semaphore>,
    signing_timeout: Duration,
    sender: &tokio::sync::mpsc::Sender<Result<HttpRequestEventResult, Status>>,
) -> Result<(), Status> {
    let SigningRequest {
        mut input,
        upstream_url,
        request_id,
        final_input_sequence,
        limits,
    } = request;
    input
        .flush()
        .await
        .map_err(|_| Status::internal("Git signing temporary storage flush failed"))?;
    let input = input.into_std().await;
    let log_upstream = upstream_url.clone();
    let log_request_id = request_id.clone();
    let _permit = signing_slots
        .acquire_owned()
        .await
        .map_err(|_| Status::unavailable("Git signing service is shutting down"))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let control = SignControl::new(Arc::clone(&cancelled), Instant::now() + signing_timeout);
    let mut worker = tokio::task::spawn_blocking(move || {
        signer.sign_receive_pack(input, Some(&upstream_url), &control)
    });
    let signed = tokio::select! {
        result = &mut worker => {
            result.map_err(|_| Status::internal("Git signing worker failed"))?
        }
        () = sender.closed() => {
            cancelled.store(true, Ordering::Release);
            let _ = worker.await;
            return Err(Status::cancelled("Git signing request was cancelled"));
        }
        () = tokio::time::sleep(signing_timeout) => {
            cancelled.store(true, Ordering::Release);
            let _ = worker.await;
            return Err(Status::deadline_exceeded("Git signing deadline exceeded"));
        }
    }
    .map_err(|error| {
        let status = if error.is_cancelled() {
            Status::cancelled("Git signing request was cancelled")
        } else if error.is_timed_out() {
            Status::deadline_exceeded("Git signing deadline exceeded")
        } else {
            Status::failed_precondition(error.public_message())
        };
        warn!(
            request_id = log_request_id,
            upstream = %log_upstream,
            category = if error.is_cancelled() { "cancelled" } else if error.is_timed_out() { "timeout" } else { "invalid_push" },
            "outgoing Git push could not be signed"
        );
        status
    })?;

    if signed.body_len > limits.deferred_bytes {
        return Err(Status::resource_exhausted(
            "signed Git request exceeds deferred storage limit",
        ));
    }

    let signed_commits = signed.signed_commits;
    let mut body = tokio::fs::File::from_std(signed.body);
    let mut chunk = vec![0; limits.unit_bytes];
    let mut output_sequence = 0u64;
    loop {
        let read = body
            .read(&mut chunk)
            .await
            .map_err(|_| Status::internal("signed Git temporary storage read failed"))?;
        if read == 0 {
            break;
        }
        output_sequence += 1;
        sender
            .send(Ok(HttpRequestEventResult {
                result: Some(http_request_event_result::Result::BodyOutput(
                    HttpRequestBodyOutput {
                        sequence: output_sequence,
                        data: chunk[..read].to_vec(),
                    },
                )),
            }))
            .await
            .map_err(|_| Status::cancelled("Git signing request was cancelled"))?;
    }
    sender
        .send(Ok(HttpRequestEventResult {
            result: Some(http_request_event_result::Result::BodyFinalize(
                HttpRequestBodyFinalize {
                    through_input_sequence: final_input_sequence,
                    through_output_sequence: output_sequence,
                    reason_code: "git_commits_signed".into(),
                    findings: vec![Finding {
                        r#type: "git.commits_signed".into(),
                        label: "Git commits signed".into(),
                        count: signed_commits,
                        confidence: "high".into(),
                        severity: "informational".into(),
                    }],
                    metadata: HashMap::from([(
                        "signed_commit_count".into(),
                        signed_commits.to_string(),
                    )]),
                    ..Default::default()
                },
            )),
        }))
        .await
        .map_err(|_| Status::cancelled("Git signing request was cancelled"))?;
    info!(
        request_id,
        upstream = %log_upstream,
        signed_commits,
        "signed outgoing Git push"
    );
    Ok(())
}

async fn send_stream_error(
    sender: &tokio::sync::mpsc::Sender<Result<HttpRequestEventResult, Status>>,
    status: Status,
) {
    let _ = sender.send(Err(status)).await;
}

fn github_upstream_url(
    target: &openshell_core::proto::HttpRequestTarget,
) -> Result<String, Status> {
    if target.scheme != "https" || target.host != "github.com" || target.port != 443 {
        return Err(Status::invalid_argument(
            "prototype supports HTTPS pushes to github.com only",
        ));
    }
    let repository_path = target
        .path
        .strip_suffix("/git-receive-pack")
        .ok_or_else(|| Status::invalid_argument("invalid Git receive-pack path"))?;
    let segments = repository_path
        .strip_prefix('/')
        .and_then(|path| path.strip_suffix(".git"))
        .map(|path| path.split('/').collect::<Vec<_>>())
        .ok_or_else(|| Status::invalid_argument("invalid GitHub repository path"))?;
    if segments.len() != 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(Status::invalid_argument("invalid GitHub repository path"));
    }
    Ok(format!("https://github.com{repository_path}"))
}

fn is_receive_pack_request(request: &HttpRequestPreflight) -> bool {
    let Some(target) = request.target.as_ref() else {
        return false;
    };
    target.method == "POST"
        && target.path.ends_with("/git-receive-pack")
        && request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-type")
                && header
                    .value
                    .split(';')
                    .next()
                    .is_some_and(|value| value.trim() == "application/x-git-receive-pack-request")
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    if cli.signing_timeout_seconds == 0 {
        return Err("signing timeout must be positive".into());
    }
    let tls_cert = std::fs::read(&cli.tls_cert)?;
    let tls_key = std::fs::read(&cli.tls_key)?;
    let extension_public_key = std::fs::read(&cli.extension_public_key)?;
    let auth = ExtensionAuth::new(
        &extension_public_key,
        &cli.expected_gateway_id,
        cli.audience,
    )
    .map_err(|error| format!("invalid extension authentication configuration: {error}"))?;
    let middleware = GitSigningMiddleware::new(
        cli.signing_key,
        cli.max_concurrent_signings,
        Duration::from_secs(cli.signing_timeout_seconds),
        auth,
    )
    .map_err(|error| format!("invalid signing configuration: {error}"))?;
    info!(bind = %cli.bind, "starting Git commit signing middleware");
    Server::builder()
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(tls_cert, tls_key)))?
        .add_service(SupervisorMiddlewareServer::new(middleware.clone()))
        .add_service(HttpRequestPreCredentialsServer::new(middleware))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use openshell_core::proto::{
        HttpHeader, HttpRequestBodyUnit, HttpRequestTarget, MiddlewareSessionEnd,
        http_request_event_result,
    };

    const TEST_PRIVATE_KEY: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAR9CeOXmiSU6YscHZWTYbW7DUc5uhdO3/OeXZg3j1+u
-----END PRIVATE KEY-----
"#;
    const TEST_PUBLIC_KEY: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuEbM0q6xP8hFxwY5kd/fD/mwr3ZpA/T7zhx6TN0DKMM=
-----END PUBLIC KEY-----
"#;

    fn authenticated_request(claims: ExtensionJwtClaims) -> Request<()> {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(EXTENSION_JWT_TYP.into());
        header.kid = Some("test-key".into());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(TEST_PRIVATE_KEY).unwrap(),
        )
        .unwrap();
        let mut request = Request::new(());
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    fn test_claims(caller_kind: ExtensionCallerKind) -> ExtensionJwtClaims {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let (sub, sandbox_id) = match caller_kind {
            ExtensionCallerKind::Gateway => ("openshell-gateway:test".into(), None),
            ExtensionCallerKind::Supervisor => (
                "spiffe://openshell/sandbox/sandbox-test".into(),
                Some("sandbox-test".into()),
            ),
        };
        ExtensionJwtClaims {
            iss: "openshell-gateway:test".into(),
            aud: "urn:openshell:extension:test:git-signing".into(),
            sub,
            iat: now,
            exp: now + 300,
            jti: "unique-test-token".into(),
            caller_kind,
            sandbox_id,
        }
    }

    #[test]
    fn extension_auth_enforces_rpc_caller_kind() {
        let auth = ExtensionAuth::new(
            TEST_PUBLIC_KEY,
            "test",
            "urn:openshell:extension:test:git-signing".into(),
        )
        .unwrap();

        assert!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Gateway)),
                Some(ExtensionCallerKind::Gateway),
            )
            .is_ok()
        );
        assert_eq!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Gateway)),
                Some(ExtensionCallerKind::Supervisor),
            )
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
        assert!(
            auth.authenticate(
                &authenticated_request(test_claims(ExtensionCallerKind::Supervisor)),
                Some(ExtensionCallerKind::Supervisor),
            )
            .is_ok()
        );
    }

    #[test]
    fn extension_auth_rejects_mismatched_supervisor_identity() {
        let auth = ExtensionAuth::new(
            TEST_PUBLIC_KEY,
            "test",
            "urn:openshell:extension:test:git-signing".into(),
        )
        .unwrap();
        let mut claims = test_claims(ExtensionCallerKind::Supervisor);
        claims.sub = "spiffe://openshell/sandbox/another-sandbox".into();

        assert_eq!(
            auth.authenticate(
                &authenticated_request(claims),
                Some(ExtensionCallerKind::Supervisor),
            )
            .unwrap_err()
            .code(),
            tonic::Code::PermissionDenied
        );
    }

    fn receive_pack_preflight() -> HttpRequestPreflight {
        HttpRequestPreflight {
            target: Some(HttpRequestTarget {
                scheme: "https".into(),
                host: "github.com".into(),
                port: 443,
                method: "POST".into(),
                path: "/NVIDIA/OpenShell.git/git-receive-pack".into(),
                ..Default::default()
            }),
            headers: vec![HttpHeader {
                name: "content-type".into(),
                value: "application/x-git-receive-pack-request".into(),
            }],
            permitted_body_modes: vec![HttpRequestBodyMode::OwnedStreamBytes as i32],
            max_payload_bytes: MAX_UNIT_BYTES as u64,
            max_deferred_bytes: 16 * 1024 * 1024,
            ..Default::default()
        }
    }

    #[test]
    fn recognizes_git_receive_pack_only() {
        let request = receive_pack_preflight();
        assert!(is_receive_pack_request(&request));

        let mut fetch = request;
        fetch.target.as_mut().unwrap().path = "/NVIDIA/OpenShell.git/git-upload-pack".into();
        assert!(!is_receive_pack_request(&fetch));
    }

    #[test]
    fn derives_a_bounded_github_upstream_url() {
        let target = receive_pack_preflight().target.unwrap();
        assert_eq!(
            github_upstream_url(&target).unwrap(),
            "https://github.com/NVIDIA/OpenShell.git"
        );

        let mut traversal = target;
        traversal.path = "/NVIDIA/../OpenShell.git/git-receive-pack".into();
        assert!(github_upstream_url(&traversal).is_err());
    }

    #[tokio::test]
    async fn owned_stream_accepts_more_than_former_unary_limit() {
        let key = tempfile::NamedTempFile::new().unwrap();
        let middleware = GitSigningMiddleware::new_for_test(key.path().to_path_buf()).unwrap();
        let mut events = vec![Ok(HttpRequestEvent {
            event: Some(http_request_event::Event::Preflight(
                receive_pack_preflight(),
            )),
        })];
        for sequence in 1..=65u64 {
            events.push(Ok(HttpRequestEvent {
                event: Some(http_request_event::Event::Body(HttpRequestBodyUnit {
                    sequence,
                    payload: Some(http_request_body_unit::Payload::Data(vec![
                        b'x';
                        MAX_UNIT_BYTES
                    ])),
                    end_of_stream: false,
                })),
            }));
        }
        events.push(Ok(HttpRequestEvent {
            event: Some(http_request_event::Event::SessionEnd(
                MiddlewareSessionEnd::default(),
            )),
        }));

        let mut results = middleware.request_stream(tokio_stream::iter(events));
        assert!(matches!(
            results.next().await.unwrap().unwrap().result,
            Some(http_request_event_result::Result::PreflightResult(_))
        ));
        for sequence in 1..=65u64 {
            let result = results.next().await.unwrap().unwrap();
            let Some(http_request_event_result::Result::BodyResult(result)) = result.result else {
                panic!("expected body ownership result");
            };
            assert_eq!(result.sequence, sequence);
            assert!(matches!(
                result.action,
                Some(http_request_body_result::Action::TakeOwnership(_))
            ));
        }
        assert!(results.next().await.is_none());
    }
}
