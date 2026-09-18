// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP request pre-credentials middleware chain execution.

use std::collections::BTreeMap;
use std::time::Duration;

use futures::StreamExt as _;
use prost::Message as _;
use tokio::sync::mpsc;
use tokio::time::Instant;

use openshell_core::proto::{
    Finding, HeaderMutation, HttpHeader, HttpRequestBodyMode, HttpRequestBodyOutput,
    HttpRequestBodyUnit, HttpRequestEvent, HttpRequestEventResult, HttpRequestPreflight,
    HttpRequestTarget, HttpRequestTrailers, MiddlewareSessionEnd, MiddlewareSessionEndReason,
    RequestContext, http_request_body_result, http_request_body_skip_remaining,
    http_request_body_transform, http_request_body_unit, http_request_event,
    http_request_event_result, http_request_preflight_result,
};

use super::{
    ChainEntry, ChainRunner, DescribedChainEntry, EXTERNAL_FINDING_LABEL,
    MAX_MIDDLEWARE_CHAIN_TIMEOUT, MAX_MIDDLEWARE_CONTEXT_BYTES, MAX_MIDDLEWARE_FINDING_BYTES,
    MAX_MIDDLEWARE_FINDINGS_PER_STAGE, MAX_MIDDLEWARE_HEADER_BYTES, MAX_MIDDLEWARE_HEADERS,
    MAX_MIDDLEWARE_METADATA_BYTES, MAX_MIDDLEWARE_METADATA_ENTRIES, MAX_MIDDLEWARE_REASON_BYTES,
    MAX_MIDDLEWARE_REASON_CODE_BYTES, MAX_MIDDLEWARE_TARGET_BYTES, MiddlewareDiagnosticPolicy,
    MiddlewareSessionAdmission, MiddlewareSessionPermit, NamespacedFinding, OnError, headers,
    is_stable_reason_code, middleware_denial_reason,
};

const STREAM_CHANNEL_CAPACITY: usize = 4;
const SESSION_END_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_RECORDED_REQUEST_INVOCATIONS: usize = 1024;

/// Largest normalized request body unit sent in streaming modes.
pub const MAX_HTTP_REQUEST_STREAM_UNIT_BYTES: usize = 64 * 1024;
/// Largest input or output representation an owned stage may retain.
///
/// The limit bounds logical storage, not memory. Implementations are expected
/// to spool large representations instead of retaining them in RAM.
pub const MAX_HTTP_REQUEST_DEFERRED_BYTES: usize = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpRequestPreflightInput {
    pub context: RequestContext,
    pub target: HttpRequestTarget,
    pub declared_body_length: Option<u64>,
    pub headers: Vec<HttpHeader>,
    pub connection_nominated_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestInvocationOutcome {
    Skip,
    BlockRequest,
    HeadersOnly,
    WholeBody,
    Stream,
    OwnedStream,
    Trailers,
    PassThrough,
    Transform,
    SkipRemaining,
    TakeOwnership,
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone)]
pub struct HttpRequestInvocation {
    pub config_name: String,
    pub implementation: String,
    pub outcome: HttpRequestInvocationOutcome,
    pub sequence: Option<u64>,
    pub input_size: usize,
    pub output_size: Option<usize>,
    pub failed: bool,
    pub stage_disabled: bool,
    pub reason_code: Option<String>,
    pub failure_category: Option<String>,
}

pub struct HttpRequestPreflightOutcome {
    pub allowed: bool,
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    pub headers: Vec<HttpHeader>,
    /// Ordered mutations to replay against the original raw header block.
    pub header_mutations: Vec<HeaderMutation>,
    pub session: Option<HttpRequestSession>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
    pub session_capacity_exhausted: bool,
}

#[derive(Debug)]
pub struct HttpRequestMiddlewareFailure {
    pub reason: String,
    pub denial: Option<super::MiddlewareDenial>,
    pub diagnostics: Box<HttpRequestDiagnostics>,
}

impl std::fmt::Display for HttpRequestMiddlewareFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for HttpRequestMiddlewareFailure {}

impl HttpRequestMiddlewareFailure {
    fn with_diagnostics(mut self, mut diagnostics: HttpRequestDiagnostics) -> Self {
        let existing = *std::mem::take(&mut self.diagnostics);
        diagnostics.findings.extend(existing.findings);
        diagnostics.metadata.extend(existing.metadata);
        diagnostics.invocations.extend(existing.invocations);
        self.diagnostics = Box::new(diagnostics);
        self
    }
}

#[derive(Debug)]
pub struct HttpRequestFinish {
    pub body_units: Vec<Vec<u8>>,
    pub trailers: Vec<HttpHeader>,
    pub body_transformed: bool,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
}

#[derive(Debug, Default)]
pub struct HttpRequestDiagnostics {
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub invocations: Vec<HttpRequestInvocation>,
}

struct HttpRequestStageTransport {
    sender: mpsc::Sender<HttpRequestEvent>,
    responses: super::HttpRequestResultStream,
    terminal_sent: bool,
}

impl HttpRequestStageTransport {
    async fn end(mut self, reason: MiddlewareSessionEndReason) {
        let _ = tokio::time::timeout(SESSION_END_TIMEOUT, self.end_inner(reason)).await;
    }

    async fn end_inner(&mut self, reason: MiddlewareSessionEndReason) {
        if self.sender.send(session_end_event(reason)).await.is_err() {
            self.terminal_sent = true;
            return;
        }
        self.terminal_sent = true;
        self.drain().await;
    }

    async fn drain(&mut self) {
        while self.responses.next().await.is_some() {}
    }
}

impl Drop for HttpRequestStageTransport {
    fn drop(&mut self) {
        if !self.terminal_sent {
            let _ = self
                .sender
                .try_send(session_end_event(MiddlewareSessionEndReason::Cancellation));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMode {
    HeadersOnly,
    WholeBody,
    Stream,
    OwnedStream,
}

struct HttpRequestStage {
    entry: DescribedChainEntry,
    transport: Option<HttpRequestStageTransport>,
    mode: StageMode,
    next_sequence: u64,
    whole_body: Vec<u8>,
    owned_input_bytes: usize,
    owned_output_bytes: usize,
    next_output_sequence: u64,
    finding_count: usize,
}

impl HttpRequestStage {
    fn is_active(&self) -> bool {
        self.transport.is_some()
    }

    async fn end(&mut self, reason: MiddlewareSessionEndReason) {
        if let Some(transport) = self.transport.take() {
            transport.end(reason).await;
        }
    }
}

pub struct HttpRequestSession {
    runner: ChainRunner,
    stages: Vec<HttpRequestStage>,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpRequestInvocation>,
    session_admission: Option<MiddlewareSessionPermit>,
    connection_nominated_headers: Vec<String>,
    body_transformed: bool,
}

impl HttpRequestSession {
    pub fn take_diagnostics(&mut self) -> HttpRequestDiagnostics {
        HttpRequestDiagnostics {
            findings: std::mem::take(&mut self.findings),
            metadata: std::mem::take(&mut self.metadata),
            invocations: std::mem::take(&mut self.invocations),
        }
    }

    #[must_use]
    pub fn stream_unit_limit(&self) -> usize {
        self.stages
            .iter()
            .filter(|stage| {
                stage.is_active()
                    && matches!(stage.mode, StageMode::Stream | StageMode::OwnedStream)
            })
            .map(|stage| {
                stage
                    .entry
                    .max_payload_bytes
                    .clamp(1, MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
            })
            .min()
            .unwrap_or(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
    }

    /// Whether any active stage must see the complete representation before
    /// the supervisor may disclose request bytes upstream.
    #[must_use]
    pub fn requires_withholding(&self) -> bool {
        self.stages.iter().any(|stage| {
            stage.is_active() && matches!(stage.mode, StageMode::WholeBody | StageMode::OwnedStream)
        })
    }

    /// Process one non-final normalized body unit through the active chain.
    pub async fn push_body(
        &mut self,
        data: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        if data.is_empty() {
            return Err(Self::failure("request_stream_unit_empty", None));
        }
        if data.len() > self.stream_unit_limit() {
            return Err(Self::failure("request_stream_unit_over_capacity", None));
        }
        let _work = self
            .runner
            .reserve_middleware_work_admission()
            .await
            .map_err(|error| Self::failure(&format!("middleware_failed: {error}"), None))?;
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        match self.process_units_from(0, vec![data], deadline).await {
            Ok(units) => Ok(units),
            Err(error) => {
                let reason = if error.denial.is_some() {
                    MiddlewareSessionEndReason::MiddlewareDenial
                } else {
                    MiddlewareSessionEndReason::MiddlewareFailure
                };
                self.end_all(reason).await;
                Err(error.with_diagnostics(self.take_diagnostics()))
            }
        }
    }

    /// Finalize all body stages and collect output in memory.
    ///
    /// Network relays should prefer [`Self::finish_to`] so owned output remains
    /// bounded by channel and storage backpressure.
    pub async fn finish(
        self,
        trailers: Vec<HttpHeader>,
    ) -> Result<HttpRequestFinish, HttpRequestMiddlewareFailure> {
        let (sender, mut receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
        let finish = self.finish_to(trailers, sender);
        let collect = async move {
            let mut units = Vec::new();
            while let Some(unit) = receiver.recv().await {
                units.push(unit);
            }
            units
        };
        let (finish, units) = tokio::join!(finish, collect);
        let mut finish = finish?;
        finish.body_units = units;
        Ok(finish)
    }

    /// Finalize all stages while sending normalized output through a bounded
    /// channel. The receiver controls backpressure and may spool to storage.
    pub async fn finish_to(
        mut self,
        mut trailers: Vec<HttpHeader>,
        output: mpsc::Sender<Vec<u8>>,
    ) -> Result<HttpRequestFinish, HttpRequestMiddlewareFailure> {
        let _work = match self.runner.reserve_middleware_work_admission().await {
            Ok(work) => work,
            Err(error) => {
                return Err(HttpRequestMiddlewareFailure {
                    reason: format!("middleware_failed: {error}"),
                    denial: None,
                    diagnostics: Box::new(self.take_diagnostics()),
                });
            }
        };
        let deadline = Instant::now() + MAX_MIDDLEWARE_CHAIN_TIMEOUT;
        for index in 0..self.stages.len() {
            let result = self.finish_stage_to(index, deadline, &output).await;
            if let Err(failure) = result {
                self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                    .await;
                return Err(failure.with_diagnostics(self.take_diagnostics()));
            }
        }

        trailers = match self.process_trailers(trailers, deadline).await {
            Ok(trailers) => trailers,
            Err(failure) => {
                self.end_all(MiddlewareSessionEndReason::MiddlewareFailure)
                    .await;
                return Err(failure.with_diagnostics(self.take_diagnostics()));
            }
        };
        self.end_all(MiddlewareSessionEndReason::Normal).await;
        self.session_admission.take();
        drop(output);
        Ok(HttpRequestFinish {
            body_units: Vec::new(),
            trailers,
            body_transformed: self.body_transformed,
            findings: self.findings,
            metadata: self.metadata,
            invocations: self.invocations,
        })
    }

    pub async fn end(mut self, reason: MiddlewareSessionEndReason) {
        self.end_all(reason).await;
    }

    async fn process_units_from(
        &mut self,
        start: usize,
        mut units: Vec<Vec<u8>>,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        // An empty replacement deletes the current unit. Streaming and owned
        // stages receive only nonempty data units followed by their own single
        // empty end-of-stream unit during `finish_stage_to`.
        units.retain(|unit| !unit.is_empty());
        for index in start..self.stages.len() {
            let mut next = Vec::new();
            for unit in units {
                let chunk_limit = if matches!(
                    self.stages[index].mode,
                    StageMode::Stream | StageMode::OwnedStream
                ) {
                    self.stages[index]
                        .entry
                        .max_payload_bytes
                        .min(MAX_HTTP_REQUEST_STREAM_UNIT_BYTES)
                } else {
                    unit.len().max(1)
                };
                for chunk in unit.chunks(chunk_limit) {
                    next.extend(
                        self.process_stage_unit(index, chunk.to_vec(), deadline)
                            .await?,
                    );
                }
            }
            units = next;
            if units.is_empty()
                && self.stages[index + 1..].iter().all(|stage| {
                    !matches!(stage.mode, StageMode::WholeBody | StageMode::OwnedStream)
                })
            {
                break;
            }
        }
        Ok(units)
    }

    async fn process_stage_unit(
        &mut self,
        index: usize,
        data: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        if !self.stages[index].is_active() || self.stages[index].mode == StageMode::HeadersOnly {
            return Ok(vec![data]);
        }
        if self.stages[index].mode == StageMode::WholeBody {
            if self.stages[index]
                .whole_body
                .len()
                .saturating_add(data.len())
                > self.stages[index].entry.max_payload_bytes
            {
                let mut original = std::mem::take(&mut self.stages[index].whole_body);
                original.extend_from_slice(&data);
                return self
                    .handle_stage_failure(index, "whole_body_over_capacity", None, original)
                    .await;
            }
            self.stages[index].whole_body.extend_from_slice(&data);
            return Ok(Vec::new());
        }

        let sequence = self.stages[index].next_sequence;
        self.stages[index].next_sequence += 1;
        if self.stages[index].mode == StageMode::OwnedStream
            && self.stages[index]
                .owned_input_bytes
                .saturating_add(data.len())
                > MAX_HTTP_REQUEST_DEFERRED_BYTES
        {
            return self
                .handle_stage_failure(
                    index,
                    "owned_input_over_capacity",
                    Some(sequence),
                    Vec::new(),
                )
                .await;
        }
        let event = body_event(sequence, data.clone(), false);
        let result = match exchange(&mut self.stages[index], event, deadline).await {
            Ok(result) => result,
            Err(reason) => {
                return self
                    .handle_stage_failure(index, &reason, Some(sequence), data)
                    .await;
            }
        };
        self.apply_body_result(index, result, sequence, data, false)
            .await
    }

    async fn finish_stage_to(
        &mut self,
        index: usize,
        deadline: Instant,
        output: &mpsc::Sender<Vec<u8>>,
    ) -> Result<(), HttpRequestMiddlewareFailure> {
        if !self.stages[index].is_active() || self.stages[index].mode == StageMode::HeadersOnly {
            return Ok(());
        }
        let mode = self.stages[index].mode;
        let data = if mode == StageMode::WholeBody {
            std::mem::take(&mut self.stages[index].whole_body)
        } else {
            Vec::new()
        };
        let sequence = self.stages[index].next_sequence;
        self.stages[index].next_sequence += 1;
        let result = match exchange(
            &mut self.stages[index],
            body_event(sequence, data.clone(), true),
            deadline,
        )
        .await
        {
            Ok(result) => result,
            Err(reason) => {
                let original = if mode == StageMode::OwnedStream {
                    Vec::new()
                } else {
                    data
                };
                let recovered = self
                    .handle_stage_failure(index, &reason, Some(sequence), original)
                    .await?;
                return self
                    .emit_downstream(index + 1, recovered, deadline, output)
                    .await;
            }
        };
        let recovered = self
            .apply_body_result(index, result, sequence, data, true)
            .await?;
        self.emit_downstream(index + 1, recovered, deadline, output)
            .await?;

        if mode == StageMode::OwnedStream && self.stages[index].is_active() {
            self.drain_owned_output(index, sequence, deadline, output)
                .await?;
        }
        Ok(())
    }

    async fn drain_owned_output(
        &mut self,
        index: usize,
        final_input_sequence: u64,
        deadline: Instant,
        output: &mpsc::Sender<Vec<u8>>,
    ) -> Result<(), HttpRequestMiddlewareFailure> {
        loop {
            let result = next_result(&mut self.stages[index], deadline)
                .await
                .map_err(|reason| {
                    Self::failure(&format!("middleware_failed: {reason}"), Some(index))
                })?;
            match result.result {
                Some(http_request_event_result::Result::BodyOutput(body_output)) => {
                    self.validate_owned_output(index, &body_output)?;
                    let downstream = self
                        .process_units_from(index + 1, vec![body_output.data], deadline)
                        .await?;
                    Self::send_output(output, downstream).await?;
                }
                Some(http_request_event_result::Result::BodyFinalize(finalize)) => {
                    let stage = &self.stages[index];
                    let final_output_sequence = stage.next_output_sequence.saturating_sub(1);
                    if finalize.through_input_sequence != final_input_sequence
                        || finalize.through_output_sequence != final_output_sequence
                    {
                        return Err(Self::failure(
                            "middleware_failed: invalid_owned_finalization",
                            Some(index),
                        ));
                    }
                    if let Err(reason) = validate_stage_diagnostics(
                        self.stages[index].finding_count,
                        &finalize.reason,
                        &finalize.reason_code,
                        &finalize.findings,
                        &finalize.metadata,
                    ) {
                        return Err(Self::failure(
                            &format!("middleware_failed: {reason}"),
                            Some(index),
                        ));
                    }
                    let reason_code =
                        (!finalize.reason_code.is_empty()).then(|| finalize.reason_code.clone());
                    self.stages[index].finding_count += finalize.findings.len();
                    collect_diagnostics(
                        &self.stages[index].entry,
                        finalize.findings,
                        finalize.metadata,
                        &mut self.findings,
                        &mut self.metadata,
                    );
                    record_request_invocation(
                        &mut self.invocations,
                        body_invocation(
                            &self.stages[index],
                            HttpRequestInvocationOutcome::Transform,
                            final_input_sequence,
                            self.stages[index].owned_input_bytes,
                            self.stages[index].owned_output_bytes,
                            reason_code,
                        ),
                    );
                    return Ok(());
                }
                _ => {
                    return Err(Self::failure(
                        "middleware_failed: unexpected_owned_output_result",
                        Some(index),
                    ));
                }
            }
        }
    }

    fn validate_owned_output(
        &mut self,
        index: usize,
        output: &HttpRequestBodyOutput,
    ) -> Result<(), HttpRequestMiddlewareFailure> {
        let stage = &mut self.stages[index];
        if output.sequence != stage.next_output_sequence {
            return Err(HttpRequestMiddlewareFailure {
                reason: "middleware_failed: invalid_owned_output_sequence".into(),
                denial: None,
                diagnostics: Box::default(),
            });
        }
        if output.data.len() > stage.entry.max_payload_bytes {
            return Err(HttpRequestMiddlewareFailure {
                reason: "middleware_failed: owned_output_unit_over_capacity".into(),
                denial: None,
                diagnostics: Box::default(),
            });
        }
        stage.owned_output_bytes = stage.owned_output_bytes.saturating_add(output.data.len());
        if stage.owned_output_bytes > MAX_HTTP_REQUEST_DEFERRED_BYTES {
            return Err(HttpRequestMiddlewareFailure {
                reason: "middleware_failed: owned_output_over_capacity".into(),
                denial: None,
                diagnostics: Box::default(),
            });
        }
        stage.next_output_sequence += 1;
        Ok(())
    }

    async fn emit_downstream(
        &mut self,
        start: usize,
        units: Vec<Vec<u8>>,
        deadline: Instant,
        output: &mpsc::Sender<Vec<u8>>,
    ) -> Result<(), HttpRequestMiddlewareFailure> {
        let units = self.process_units_from(start, units, deadline).await?;
        Self::send_output(output, units).await
    }

    async fn send_output(
        output: &mpsc::Sender<Vec<u8>>,
        units: Vec<Vec<u8>>,
    ) -> Result<(), HttpRequestMiddlewareFailure> {
        for unit in units {
            output
                .send(unit)
                .await
                .map_err(|_| HttpRequestMiddlewareFailure {
                    reason: "request_output_consumer_closed".into(),
                    denial: None,
                    diagnostics: Box::default(),
                })?;
        }
        Ok(())
    }

    async fn apply_body_result(
        &mut self,
        index: usize,
        result: HttpRequestEventResult,
        sequence: u64,
        original: Vec<u8>,
        end_of_stream: bool,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        let Some(http_request_event_result::Result::BodyResult(result)) = result.result else {
            return self
                .handle_stage_failure(index, "unexpected_body_result", Some(sequence), original)
                .await;
        };
        if result.sequence != sequence {
            return self
                .handle_stage_failure(index, "invalid_body_sequence", Some(sequence), original)
                .await;
        }
        if let Err(reason) = validate_stage_diagnostics(
            self.stages[index].finding_count,
            &result.reason,
            &result.reason_code,
            &result.findings,
            &result.metadata,
        ) {
            return self
                .handle_stage_failure(index, reason, Some(sequence), original)
                .await;
        }
        let reason_code = (!result.reason_code.is_empty()).then(|| result.reason_code.clone());
        self.stages[index].finding_count += result.findings.len();
        collect_diagnostics(
            &self.stages[index].entry,
            result.findings,
            result.metadata,
            &mut self.findings,
            &mut self.metadata,
        );

        let owned = self.stages[index].mode == StageMode::OwnedStream;
        let action = result.action;
        if owned {
            if !matches!(
                action,
                Some(http_request_body_result::Action::TakeOwnership(_))
            ) {
                return self
                    .handle_stage_failure(
                        index,
                        "owned_stage_did_not_take_ownership",
                        Some(sequence),
                        Vec::new(),
                    )
                    .await;
            }
            self.stages[index].owned_input_bytes = self.stages[index]
                .owned_input_bytes
                .saturating_add(original.len());
            self.body_transformed = true;
            record_request_invocation(
                &mut self.invocations,
                body_invocation(
                    &self.stages[index],
                    HttpRequestInvocationOutcome::TakeOwnership,
                    sequence,
                    original.len(),
                    0,
                    reason_code,
                ),
            );
            return Ok(Vec::new());
        }

        let (outcome, replacement, skip_remaining) = match action {
            Some(http_request_body_result::Action::PassThrough(_)) => (
                HttpRequestInvocationOutcome::PassThrough,
                original.clone(),
                false,
            ),
            Some(http_request_body_result::Action::Transform(transform)) => {
                let Some(http_request_body_transform::Replacement::Data(data)) =
                    transform.replacement
                else {
                    return self
                        .handle_stage_failure(
                            index,
                            "missing_body_replacement",
                            Some(sequence),
                            original,
                        )
                        .await;
                };
                if data.len() > self.stages[index].entry.max_payload_bytes {
                    return self
                        .handle_stage_failure(
                            index,
                            "body_replacement_over_capacity",
                            Some(sequence),
                            original,
                        )
                        .await;
                }
                self.body_transformed = true;
                (HttpRequestInvocationOutcome::Transform, data, false)
            }
            Some(http_request_body_result::Action::SkipRemaining(skip)) => {
                let replacement = match skip.current {
                    Some(http_request_body_skip_remaining::Current::PassThrough(_)) => {
                        original.clone()
                    }
                    Some(http_request_body_skip_remaining::Current::Transform(transform)) => {
                        let Some(http_request_body_transform::Replacement::Data(data)) =
                            transform.replacement
                        else {
                            return self
                                .handle_stage_failure(
                                    index,
                                    "missing_body_replacement",
                                    Some(sequence),
                                    original,
                                )
                                .await;
                        };
                        if data.len() > self.stages[index].entry.max_payload_bytes {
                            return self
                                .handle_stage_failure(
                                    index,
                                    "body_replacement_over_capacity",
                                    Some(sequence),
                                    original,
                                )
                                .await;
                        }
                        self.body_transformed = true;
                        data
                    }
                    None => {
                        return self
                            .handle_stage_failure(
                                index,
                                "missing_skip_remaining_action",
                                Some(sequence),
                                original,
                            )
                            .await;
                    }
                };
                (
                    HttpRequestInvocationOutcome::SkipRemaining,
                    replacement,
                    true,
                )
            }
            Some(http_request_body_result::Action::BlockRequest(_)) => {
                let denial = super::MiddlewareDenial {
                    config_name: self.stages[index].entry.entry.name.clone(),
                    reason_code: reason_code.clone(),
                };
                record_request_invocation(
                    &mut self.invocations,
                    body_invocation(
                        &self.stages[index],
                        HttpRequestInvocationOutcome::BlockRequest,
                        sequence,
                        original.len(),
                        0,
                        reason_code,
                    ),
                );
                self.end_all(MiddlewareSessionEndReason::MiddlewareDenial)
                    .await;
                return Err(HttpRequestMiddlewareFailure {
                    reason: middleware_denial_reason(
                        &denial.config_name,
                        denial.reason_code.as_deref(),
                    ),
                    denial: Some(denial),
                    diagnostics: Box::default(),
                });
            }
            Some(http_request_body_result::Action::TakeOwnership(_)) | None => {
                return self
                    .handle_stage_failure(index, "invalid_body_action", Some(sequence), original)
                    .await;
            }
        };
        record_request_invocation(
            &mut self.invocations,
            body_invocation(
                &self.stages[index],
                outcome,
                sequence,
                original.len(),
                replacement.len(),
                reason_code,
            ),
        );
        if skip_remaining {
            self.stages[index]
                .end(MiddlewareSessionEndReason::StageSkipped)
                .await;
            self.release_admission_if_idle();
        } else if end_of_stream {
            // Keep the transport open for the trailers event.
        }
        Ok(vec![replacement])
    }

    async fn process_trailers(
        &mut self,
        mut trailers: Vec<HttpHeader>,
        deadline: Instant,
    ) -> Result<Vec<HttpHeader>, HttpRequestMiddlewareFailure> {
        for index in 0..self.stages.len() {
            if !self.stages[index].is_active() || self.stages[index].mode == StageMode::HeadersOnly
            {
                continue;
            }
            let event = HttpRequestEvent {
                event: Some(http_request_event::Event::Trailers(HttpRequestTrailers {
                    headers: trailers.clone(),
                })),
            };
            let result = match exchange(&mut self.stages[index], event, deadline).await {
                Ok(result) => result,
                Err(reason) => {
                    trailers = self
                        .handle_trailer_failure(index, &reason, trailers)
                        .await?;
                    continue;
                }
            };
            let Some(http_request_event_result::Result::TrailersResult(result)) = result.result
            else {
                trailers = self
                    .handle_trailer_failure(index, "unexpected_trailers_result", trailers)
                    .await?;
                continue;
            };
            if let Err(reason) = validate_stage_diagnostics(
                self.stages[index].finding_count,
                &result.reason,
                &result.reason_code,
                &result.findings,
                &result.metadata,
            ) {
                trailers = self.handle_trailer_failure(index, reason, trailers).await?;
                continue;
            }
            self.stages[index].finding_count += result.findings.len();
            let updated = match headers::apply(
                headers::HeaderAuthority::RequestTrailers,
                &trailers,
                &self.connection_nominated_headers,
                &result.trailer_mutations,
            ) {
                Ok(updated) => updated,
                Err(error) => {
                    let reason = self.stages[index].entry.service.as_ref().map_or_else(
                        || error.to_string(),
                        |service| {
                            service
                                .diagnostic_policy
                                .header_mutation_error_reason(&error)
                        },
                    );
                    trailers = self
                        .handle_trailer_failure(index, &reason, trailers)
                        .await?;
                    continue;
                }
            };
            collect_diagnostics(
                &self.stages[index].entry,
                result.findings,
                result.metadata,
                &mut self.findings,
                &mut self.metadata,
            );
            record_request_invocation(
                &mut self.invocations,
                HttpRequestInvocation {
                    config_name: self.stages[index].entry.entry.name.clone(),
                    implementation: self.stages[index].entry.entry.implementation.clone(),
                    outcome: HttpRequestInvocationOutcome::Trailers,
                    sequence: None,
                    input_size: encoded_header_bytes(&trailers),
                    output_size: Some(encoded_header_bytes(&updated)),
                    failed: false,
                    stage_disabled: false,
                    reason_code: (!result.reason_code.is_empty()).then_some(result.reason_code),
                    failure_category: None,
                },
            );
            trailers = updated;
        }
        Ok(trailers)
    }

    async fn handle_trailer_failure(
        &mut self,
        index: usize,
        reason: &str,
        original: Vec<HttpHeader>,
    ) -> Result<Vec<HttpHeader>, HttpRequestMiddlewareFailure> {
        let stage = &mut self.stages[index];
        let fail_open = stage.entry.on_error() == OnError::FailOpen;
        record_request_invocation(
            &mut self.invocations,
            HttpRequestInvocation {
                config_name: stage.entry.entry.name.clone(),
                implementation: stage.entry.entry.implementation.clone(),
                outcome: if fail_open {
                    HttpRequestInvocationOutcome::FailOpen
                } else {
                    HttpRequestInvocationOutcome::FailClosed
                },
                sequence: None,
                input_size: encoded_header_bytes(&original),
                output_size: None,
                failed: true,
                stage_disabled: true,
                reason_code: None,
                failure_category: Some(request_failure_category(reason).into()),
            },
        );
        stage
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.release_admission_if_idle();
        if fail_open {
            Ok(original)
        } else {
            Err(HttpRequestMiddlewareFailure {
                reason: format!("middleware_failed: {reason}"),
                denial: None,
                diagnostics: Box::default(),
            })
        }
    }

    async fn handle_stage_failure(
        &mut self,
        index: usize,
        reason: &str,
        sequence: Option<u64>,
        original: Vec<u8>,
    ) -> Result<Vec<Vec<u8>>, HttpRequestMiddlewareFailure> {
        let stage = &mut self.stages[index];
        let fail_open =
            stage.entry.on_error() == OnError::FailOpen && stage.mode != StageMode::OwnedStream;
        record_request_invocation(
            &mut self.invocations,
            HttpRequestInvocation {
                config_name: stage.entry.entry.name.clone(),
                implementation: stage.entry.entry.implementation.clone(),
                outcome: if fail_open {
                    HttpRequestInvocationOutcome::FailOpen
                } else {
                    HttpRequestInvocationOutcome::FailClosed
                },
                sequence,
                input_size: original.len(),
                output_size: None,
                failed: true,
                stage_disabled: true,
                reason_code: None,
                failure_category: Some(request_failure_category(reason).into()),
            },
        );
        stage
            .end(MiddlewareSessionEndReason::MiddlewareFailure)
            .await;
        self.release_admission_if_idle();
        if fail_open {
            Ok(vec![original])
        } else {
            Err(HttpRequestMiddlewareFailure {
                reason: format!("middleware_failed: {reason}"),
                denial: None,
                diagnostics: Box::default(),
            })
        }
    }

    async fn end_all(&mut self, reason: MiddlewareSessionEndReason) {
        for stage in &mut self.stages {
            stage.end(reason).await;
        }
        self.session_admission.take();
    }

    fn release_admission_if_idle(&mut self) {
        if self.stages.iter().all(|stage| !stage.is_active()) {
            self.session_admission.take();
        }
    }

    fn failure(reason: &str, _index: Option<usize>) -> HttpRequestMiddlewareFailure {
        HttpRequestMiddlewareFailure {
            reason: reason.to_string(),
            // Transport and protocol failures are not authoritative service
            // denials. The caller still fails closed when policy requires it,
            // but must not present the failure as an accepted block decision.
            denial: None,
            diagnostics: Box::default(),
        }
    }
}

impl ChainRunner {
    pub async fn preflight_http_request(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        let described = self.describe_chain(entries).await?;
        self.preflight_described_http_request(described, input)
            .await
    }

    pub async fn preflight_described_http_request(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        self.preflight_described_http_request_with_owned(described, input, true)
            .await
    }

    /// Open a request stream with explicit control over storage-backed owned
    /// mode. Complete-body compatibility callers disable owned mode because
    /// their result is necessarily materialized in memory.
    pub(crate) async fn preflight_described_http_request_with_owned(
        &self,
        described: Vec<DescribedChainEntry>,
        input: HttpRequestPreflightInput,
        allow_owned: bool,
    ) -> miette::Result<HttpRequestPreflightOutcome> {
        if described.is_empty() {
            return Ok(empty_preflight_outcome(input.headers));
        }
        if validate_preflight_input(&input).is_err() {
            return Ok(preflight_input_failure(
                &described,
                input.headers,
                "request_input_over_capacity",
            ));
        }
        let session_admission = match self.try_reserve_middleware_session() {
            MiddlewareSessionAdmission::Admitted(admission) => admission,
            MiddlewareSessionAdmission::AtCapacity => {
                return Ok(session_capacity_exhausted(described, input.headers));
            }
        };
        let work_admission = self.reserve_middleware_work().await?;
        let _work = match work_admission {
            super::MiddlewareWorkAdmissionOutcome::Admitted(admission) => admission,
            super::MiddlewareWorkAdmissionOutcome::QueueExhausted => {
                return Ok(session_capacity_exhausted(described, input.headers));
            }
        };
        let mut headers = input.headers.clone();
        let mut header_mutations = Vec::new();
        let mut stages = Vec::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut invocations = Vec::new();

        for entry in described {
            let Some(service) = entry.service.as_ref() else {
                if let Some(reason) =
                    collect_preflight_failure(&entry, "binding_not_described", &mut invocations)
                {
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            let permitted_modes = permitted_body_modes(&input, &entry, allow_owned);
            let (sender, receiver) = mpsc::channel(STREAM_CHANNEL_CAPACITY);
            let preflight = HttpRequestPreflight {
                context: Some(input.context.clone()),
                target: Some(input.target.clone()),
                headers: headers.clone(),
                middleware_name: entry.entry.implementation.clone(),
                config: Some(entry.entry.config.clone()),
                max_payload_bytes: entry.max_payload_bytes as u64,
                permitted_body_modes: permitted_modes.clone(),
                max_deferred_bytes: if entry.on_error() == OnError::FailClosed {
                    MAX_HTTP_REQUEST_DEFERRED_BYTES as u64
                } else {
                    0
                },
                declared_body_length: input.declared_body_length,
            };
            let timeout = entry.timeout;
            let opened = tokio::time::timeout(timeout, async {
                sender
                    .send(HttpRequestEvent {
                        event: Some(http_request_event::Event::Preflight(preflight)),
                    })
                    .await
                    .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
                let mut responses = service
                    .service
                    .open_http_request_pre_credentials(receiver)
                    .await?;
                let response = responses.next().await.ok_or_else(|| {
                    tonic::Status::unavailable("middleware result stream closed")
                })??;
                Ok::<_, tonic::Status>((responses, response))
            })
            .await;
            let (responses, response) = match opened {
                Ok(Ok(opened)) => opened,
                Ok(Err(error)) => {
                    let reason = service.diagnostic_policy.error_reason(&error);
                    if let Some(reason) =
                        collect_preflight_failure(&entry, &reason, &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            header_mutations,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
                Err(_) => {
                    if let Some(reason) =
                        collect_preflight_failure(&entry, "middleware_timeout", &mut invocations)
                    {
                        end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareFailure)
                            .await;
                        return Ok(failed_preflight_outcome(
                            headers,
                            header_mutations,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                    continue;
                }
            };
            let mut current_stage = HttpRequestStage {
                entry: entry.clone(),
                transport: Some(HttpRequestStageTransport {
                    sender,
                    responses,
                    terminal_sent: false,
                }),
                mode: StageMode::HeadersOnly,
                next_sequence: 1,
                whole_body: Vec::new(),
                owned_input_bytes: 0,
                owned_output_bytes: 0,
                next_output_sequence: 1,
                finding_count: 0,
            };
            let Some(http_request_event_result::Result::PreflightResult(result)) = response.result
            else {
                if let Some(reason) = handle_opened_preflight_failure(
                    &entry,
                    &mut current_stage,
                    &mut stages,
                    "unexpected_preflight_result",
                    &mut invocations,
                )
                .await
                {
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            };
            if let Err(reason) = validate_diagnostics(
                &result.reason,
                &result.reason_code,
                &result.findings,
                &result.metadata,
            ) {
                if let Some(reason) = handle_opened_preflight_failure(
                    &entry,
                    &mut current_stage,
                    &mut stages,
                    reason,
                    &mut invocations,
                )
                .await
                {
                    return Ok(failed_preflight_outcome(
                        headers,
                        header_mutations,
                        reason,
                        findings,
                        metadata,
                        invocations,
                    ));
                }
                continue;
            }
            let reason_code = (!result.reason_code.is_empty()).then(|| result.reason_code.clone());
            current_stage.finding_count = result.findings.len();
            let result_findings = result.findings;
            let result_metadata = result.metadata;
            match result.action {
                Some(http_request_preflight_result::Action::Skip(_)) => {
                    collect_diagnostics(
                        &entry,
                        result_findings,
                        result_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(preflight_invocation(
                        &entry,
                        HttpRequestInvocationOutcome::Skip,
                        reason_code,
                    ));
                    current_stage
                        .end(MiddlewareSessionEndReason::StageSkipped)
                        .await;
                }
                Some(http_request_preflight_result::Action::Inspect(inspect)) => {
                    let mode = match validate_inspect(&inspect, &permitted_modes) {
                        Ok(mode) => mode,
                        Err(reason) => {
                            if let Some(reason) = handle_opened_preflight_failure(
                                &entry,
                                &mut current_stage,
                                &mut stages,
                                reason,
                                &mut invocations,
                            )
                            .await
                            {
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    header_mutations,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    let updated = match headers::apply(
                        headers::HeaderAuthority::Request,
                        &headers,
                        &input.connection_nominated_headers,
                        &inspect.header_mutations,
                    ) {
                        Ok(updated) => updated,
                        Err(error) => {
                            let reason = service
                                .diagnostic_policy
                                .header_mutation_error_reason(&error);
                            if let Some(reason) = handle_opened_preflight_failure(
                                &entry,
                                &mut current_stage,
                                &mut stages,
                                &reason,
                                &mut invocations,
                            )
                            .await
                            {
                                return Ok(failed_preflight_outcome(
                                    headers,
                                    header_mutations,
                                    reason,
                                    findings,
                                    metadata,
                                    invocations,
                                ));
                            }
                            continue;
                        }
                    };
                    headers = updated;
                    header_mutations.extend(inspect.header_mutations);
                    collect_diagnostics(
                        &entry,
                        result_findings,
                        result_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(preflight_invocation(
                        &entry,
                        match mode {
                            StageMode::HeadersOnly => HttpRequestInvocationOutcome::HeadersOnly,
                            StageMode::WholeBody => HttpRequestInvocationOutcome::WholeBody,
                            StageMode::Stream => HttpRequestInvocationOutcome::Stream,
                            StageMode::OwnedStream => HttpRequestInvocationOutcome::OwnedStream,
                        },
                        reason_code,
                    ));
                    current_stage.mode = mode;
                    if mode == StageMode::HeadersOnly {
                        current_stage.end(MiddlewareSessionEndReason::Normal).await;
                    } else {
                        stages.push(current_stage);
                    }
                }
                Some(http_request_preflight_result::Action::BlockRequest(_)) => {
                    collect_diagnostics(
                        &entry,
                        result_findings,
                        result_metadata,
                        &mut findings,
                        &mut metadata,
                    );
                    invocations.push(preflight_invocation(
                        &entry,
                        HttpRequestInvocationOutcome::BlockRequest,
                        reason_code.clone(),
                    ));
                    stages.push(current_stage);
                    end_stages(&mut stages, MiddlewareSessionEndReason::MiddlewareDenial).await;
                    let denial = super::MiddlewareDenial {
                        config_name: entry.entry.name.clone(),
                        reason_code,
                    };
                    return Ok(HttpRequestPreflightOutcome {
                        allowed: false,
                        reason: middleware_denial_reason(
                            &denial.config_name,
                            denial.reason_code.as_deref(),
                        ),
                        denial: Some(denial),
                        headers,
                        header_mutations,
                        session: None,
                        findings,
                        metadata,
                        invocations,
                        session_capacity_exhausted: false,
                    });
                }
                None => {
                    if let Some(reason) = handle_opened_preflight_failure(
                        &entry,
                        &mut current_stage,
                        &mut stages,
                        "missing_preflight_action",
                        &mut invocations,
                    )
                    .await
                    {
                        return Ok(failed_preflight_outcome(
                            headers,
                            header_mutations,
                            reason,
                            findings,
                            metadata,
                            invocations,
                        ));
                    }
                }
            }
        }

        let session = (!stages.is_empty()).then(|| HttpRequestSession {
            runner: self.clone(),
            stages,
            findings: Vec::new(),
            metadata: BTreeMap::new(),
            invocations: Vec::new(),
            session_admission: Some(session_admission),
            connection_nominated_headers: input.connection_nominated_headers,
            body_transformed: false,
        });
        Ok(HttpRequestPreflightOutcome {
            allowed: true,
            reason: String::new(),
            denial: None,
            headers,
            header_mutations,
            session,
            findings,
            metadata,
            invocations,
            session_capacity_exhausted: false,
        })
    }
}

async fn exchange(
    stage: &mut HttpRequestStage,
    event: HttpRequestEvent,
    chain_deadline: Instant,
) -> Result<HttpRequestEventResult, String> {
    let remaining = chain_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("middleware_chain_timeout".into());
    }
    let timeout = stage.entry.timeout.min(remaining);
    let Some(transport) = stage.transport.as_mut() else {
        return Err("middleware_stream_closed".into());
    };
    match tokio::time::timeout(timeout, async {
        transport
            .sender
            .send(event)
            .await
            .map_err(|_| tonic::Status::unavailable("middleware request stream closed"))?;
        transport
            .responses
            .next()
            .await
            .ok_or_else(|| tonic::Status::unavailable("middleware result stream closed"))?
    })
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => {
            let policy = stage
                .entry
                .service
                .as_ref()
                .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
                    service.diagnostic_policy
                });
            Err(policy.error_reason(&error))
        }
        Err(_) => Err("middleware_timeout".into()),
    }
}

async fn next_result(
    stage: &mut HttpRequestStage,
    chain_deadline: Instant,
) -> Result<HttpRequestEventResult, String> {
    let remaining = chain_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("middleware_chain_timeout".into());
    }
    let timeout = stage.entry.timeout.min(remaining);
    let Some(transport) = stage.transport.as_mut() else {
        return Err("middleware_stream_closed".into());
    };
    match tokio::time::timeout(timeout, transport.responses.next()).await {
        Ok(Some(Ok(result))) => Ok(result),
        Ok(Some(Err(error))) => Err(stage
            .entry
            .service
            .as_ref()
            .map_or(MiddlewareDiagnosticPolicy::Preserve, |service| {
                service.diagnostic_policy
            })
            .error_reason(&error)),
        Ok(None) => Err("middleware_result_stream_closed".into()),
        Err(_) => Err("middleware_timeout".into()),
    }
}

fn body_event(sequence: u64, data: Vec<u8>, end_of_stream: bool) -> HttpRequestEvent {
    HttpRequestEvent {
        event: Some(http_request_event::Event::Body(HttpRequestBodyUnit {
            sequence,
            payload: Some(http_request_body_unit::Payload::Data(data)),
            end_of_stream,
        })),
    }
}

fn session_end_event(reason: MiddlewareSessionEndReason) -> HttpRequestEvent {
    HttpRequestEvent {
        event: Some(http_request_event::Event::SessionEnd(
            MiddlewareSessionEnd {
                reason: reason as i32,
                protocol_error: None,
            },
        )),
    }
}

fn validate_preflight_input(input: &HttpRequestPreflightInput) -> miette::Result<()> {
    if input.context.encoded_len() > MAX_MIDDLEWARE_CONTEXT_BYTES {
        return Err(miette::miette!("request context exceeds platform limit"));
    }
    if input.target.encoded_len() > MAX_MIDDLEWARE_TARGET_BYTES {
        return Err(miette::miette!("request target exceeds platform limit"));
    }
    if input.headers.len() > MAX_MIDDLEWARE_HEADERS {
        return Err(miette::miette!(
            "request header count exceeds platform limit"
        ));
    }
    if encoded_header_bytes(&input.headers) > MAX_MIDDLEWARE_HEADER_BYTES {
        return Err(miette::miette!("request headers exceed platform limit"));
    }
    Ok(())
}

fn validate_diagnostics(
    reason: &str,
    reason_code: &str,
    findings: &[Finding],
    metadata: &std::collections::HashMap<String, String>,
) -> Result<(), &'static str> {
    if reason.len() > MAX_MIDDLEWARE_REASON_BYTES {
        return Err("request_reason_over_capacity");
    }
    if !reason_code.is_empty()
        && (reason_code.len() > MAX_MIDDLEWARE_REASON_CODE_BYTES
            || !is_stable_reason_code(reason_code))
    {
        return Err("request_reason_code_invalid");
    }
    if findings.len() > MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
        return Err("request_findings_over_capacity");
    }
    if findings
        .iter()
        .any(|finding| finding.encoded_len() > MAX_MIDDLEWARE_FINDING_BYTES)
    {
        return Err("request_finding_over_capacity");
    }
    if metadata.len() > MAX_MIDDLEWARE_METADATA_ENTRIES {
        return Err("request_metadata_count_over_capacity");
    }
    if metadata.iter().fold(0usize, |total, (key, value)| {
        total.saturating_add(key.len()).saturating_add(value.len())
    }) > MAX_MIDDLEWARE_METADATA_BYTES
    {
        return Err("request_metadata_bytes_over_capacity");
    }
    Ok(())
}

fn validate_stage_diagnostics(
    existing_findings: usize,
    reason: &str,
    reason_code: &str,
    findings: &[Finding],
    metadata: &std::collections::HashMap<String, String>,
) -> Result<(), &'static str> {
    validate_diagnostics(reason, reason_code, findings, metadata)?;
    if existing_findings.saturating_add(findings.len()) > MAX_MIDDLEWARE_FINDINGS_PER_STAGE {
        return Err("request_findings_over_capacity");
    }
    Ok(())
}

fn permitted_body_modes(
    input: &HttpRequestPreflightInput,
    entry: &DescribedChainEntry,
    allow_owned: bool,
) -> Vec<i32> {
    let mut modes = vec![HttpRequestBodyMode::HeadersOnly as i32];
    if input
        .declared_body_length
        .is_none_or(|length| length <= entry.max_payload_bytes as u64)
    {
        modes.push(HttpRequestBodyMode::WholeBodyBytes as i32);
    }
    if entry.max_payload_bytes > 0 {
        modes.push(HttpRequestBodyMode::StreamBytes as i32);
        if allow_owned && entry.on_error() == OnError::FailClosed {
            modes.push(HttpRequestBodyMode::OwnedStreamBytes as i32);
        }
    }
    modes
}

fn validate_inspect(
    inspect: &openshell_core::proto::HttpRequestPreflightInspect,
    permitted_modes: &[i32],
) -> Result<StageMode, &'static str> {
    if !permitted_modes.contains(&inspect.body_mode) {
        return Err("request_body_mode_not_permitted");
    }
    match HttpRequestBodyMode::try_from(inspect.body_mode) {
        Ok(HttpRequestBodyMode::HeadersOnly) => Ok(StageMode::HeadersOnly),
        Ok(HttpRequestBodyMode::WholeBodyBytes) => Ok(StageMode::WholeBody),
        Ok(HttpRequestBodyMode::StreamBytes) => Ok(StageMode::Stream),
        Ok(HttpRequestBodyMode::OwnedStreamBytes) => Ok(StageMode::OwnedStream),
        Ok(HttpRequestBodyMode::Unspecified) | Err(_) => Err("invalid_request_body_mode"),
    }
}

fn encoded_header_bytes(headers: &[HttpHeader]) -> usize {
    headers.iter().fold(0usize, |total, header| {
        total.saturating_add(header.encoded_len())
    })
}

fn collect_diagnostics(
    entry: &DescribedChainEntry,
    mut findings: Vec<Finding>,
    mut metadata: std::collections::HashMap<String, String>,
    all_findings: &mut Vec<NamespacedFinding>,
    all_metadata: &mut BTreeMap<String, BTreeMap<String, String>>,
) {
    if entry
        .service
        .as_ref()
        .is_some_and(|service| service.diagnostic_policy == MiddlewareDiagnosticPolicy::Normalize)
    {
        metadata.clear();
        for finding in &mut findings {
            finding.r#type = format!("{}.finding", entry.entry.implementation);
            finding.label = EXTERNAL_FINDING_LABEL.to_string();
            finding.confidence.clear();
            finding.severity = "medium".into();
        }
    }
    all_findings.extend(findings.into_iter().map(|finding| NamespacedFinding {
        middleware: entry.entry.name.clone(),
        finding,
    }));
    if !metadata.is_empty() {
        all_metadata.insert(entry.entry.name.clone(), metadata.into_iter().collect());
    }
}

fn body_invocation(
    stage: &HttpRequestStage,
    outcome: HttpRequestInvocationOutcome,
    sequence: u64,
    input_size: usize,
    output_size: usize,
    reason_code: Option<String>,
) -> HttpRequestInvocation {
    HttpRequestInvocation {
        config_name: stage.entry.entry.name.clone(),
        implementation: stage.entry.entry.implementation.clone(),
        outcome,
        sequence: Some(sequence),
        input_size,
        output_size: Some(output_size),
        failed: false,
        stage_disabled: false,
        reason_code,
        failure_category: None,
    }
}

fn record_request_invocation(
    invocations: &mut Vec<HttpRequestInvocation>,
    invocation: HttpRequestInvocation,
) {
    if invocations.len() < MAX_RECORDED_REQUEST_INVOCATIONS {
        invocations.push(invocation);
        return;
    }

    let index = invocations
        .iter()
        .position(|existing| existing.config_name == invocation.config_name)
        .unwrap_or(invocations.len() - 1);
    let existing = &mut invocations[index];
    existing.sequence = invocation.sequence.or(existing.sequence);
    existing.input_size = existing.input_size.saturating_add(invocation.input_size);
    existing.output_size = match (existing.output_size, invocation.output_size) {
        (_, None) if invocation.failed => None,
        (Some(existing), Some(incoming)) => Some(existing.saturating_add(incoming)),
        (None, Some(incoming)) => Some(incoming),
        (existing, None) => existing,
    };
    existing.failed |= invocation.failed;
    existing.stage_disabled |= invocation.stage_disabled;
    if invocation.reason_code.is_some() {
        existing.reason_code = invocation.reason_code;
    }
    if invocation.failure_category.is_some() {
        existing.failure_category = invocation.failure_category;
    }
    if request_invocation_priority(invocation.outcome)
        >= request_invocation_priority(existing.outcome)
    {
        existing.outcome = invocation.outcome;
    }
}

fn request_invocation_priority(outcome: HttpRequestInvocationOutcome) -> u8 {
    match outcome {
        HttpRequestInvocationOutcome::BlockRequest | HttpRequestInvocationOutcome::FailClosed => 5,
        HttpRequestInvocationOutcome::FailOpen => 4,
        HttpRequestInvocationOutcome::Transform => 3,
        HttpRequestInvocationOutcome::SkipRemaining
        | HttpRequestInvocationOutcome::TakeOwnership => 2,
        HttpRequestInvocationOutcome::Skip
        | HttpRequestInvocationOutcome::HeadersOnly
        | HttpRequestInvocationOutcome::WholeBody
        | HttpRequestInvocationOutcome::Stream
        | HttpRequestInvocationOutcome::OwnedStream
        | HttpRequestInvocationOutcome::Trailers
        | HttpRequestInvocationOutcome::PassThrough => 1,
    }
}

fn preflight_invocation(
    entry: &DescribedChainEntry,
    outcome: HttpRequestInvocationOutcome,
    reason_code: Option<String>,
) -> HttpRequestInvocation {
    HttpRequestInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome,
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: false,
        stage_disabled: false,
        reason_code,
        failure_category: None,
    }
}

fn collect_preflight_failure(
    entry: &DescribedChainEntry,
    reason: &str,
    invocations: &mut Vec<HttpRequestInvocation>,
) -> Option<String> {
    let fail_closed = entry.on_error() == OnError::FailClosed;
    invocations.push(HttpRequestInvocation {
        config_name: entry.entry.name.clone(),
        implementation: entry.entry.implementation.clone(),
        outcome: if fail_closed {
            HttpRequestInvocationOutcome::FailClosed
        } else {
            HttpRequestInvocationOutcome::FailOpen
        },
        sequence: None,
        input_size: 0,
        output_size: None,
        failed: true,
        stage_disabled: true,
        reason_code: None,
        failure_category: Some(request_failure_category(reason).into()),
    });
    fail_closed.then(|| format!("middleware_failed: {reason}"))
}

fn empty_preflight_outcome(headers: Vec<HttpHeader>) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: true,
        reason: String::new(),
        denial: None,
        headers,
        header_mutations: Vec::new(),
        session: None,
        findings: Vec::new(),
        metadata: BTreeMap::new(),
        invocations: Vec::new(),
        session_capacity_exhausted: false,
    }
}

fn failed_preflight_outcome(
    headers: Vec<HttpHeader>,
    header_mutations: Vec<HeaderMutation>,
    reason: String,
    findings: Vec<NamespacedFinding>,
    metadata: BTreeMap<String, BTreeMap<String, String>>,
    invocations: Vec<HttpRequestInvocation>,
) -> HttpRequestPreflightOutcome {
    HttpRequestPreflightOutcome {
        allowed: false,
        reason,
        denial: None,
        headers,
        header_mutations,
        session: None,
        findings,
        metadata,
        invocations,
        session_capacity_exhausted: false,
    }
}

fn preflight_input_failure(
    entries: &[DescribedChainEntry],
    headers: Vec<HttpHeader>,
    reason: &str,
) -> HttpRequestPreflightOutcome {
    let mut invocations = Vec::new();
    let denied = entries
        .iter()
        .find_map(|entry| collect_preflight_failure(entry, reason, &mut invocations));
    if let Some(reason) = denied {
        failed_preflight_outcome(
            headers,
            Vec::new(),
            reason,
            Vec::new(),
            BTreeMap::new(),
            invocations,
        )
    } else {
        HttpRequestPreflightOutcome {
            invocations,
            ..empty_preflight_outcome(headers)
        }
    }
}

fn session_capacity_exhausted(
    entries: Vec<DescribedChainEntry>,
    headers: Vec<HttpHeader>,
) -> HttpRequestPreflightOutcome {
    let mut outcome = preflight_input_failure(&entries, headers, "session_capacity_exhausted");
    outcome.session_capacity_exhausted = true;
    outcome
}

async fn end_stages(stages: &mut [HttpRequestStage], reason: MiddlewareSessionEndReason) {
    for stage in stages {
        stage.end(reason).await;
    }
}

async fn handle_opened_preflight_failure(
    entry: &DescribedChainEntry,
    current_stage: &mut HttpRequestStage,
    prior_stages: &mut [HttpRequestStage],
    reason: &str,
    invocations: &mut Vec<HttpRequestInvocation>,
) -> Option<String> {
    current_stage
        .end(MiddlewareSessionEndReason::MiddlewareFailure)
        .await;
    let failure = collect_preflight_failure(entry, reason, invocations);
    if failure.is_some() {
        end_stages(prior_stages, MiddlewareSessionEndReason::MiddlewareFailure).await;
    }
    failure
}

fn request_failure_category(reason: &str) -> &'static str {
    if reason.contains("timeout") {
        "timeout"
    } else if reason.contains("capacity") {
        "capacity"
    } else if reason.contains("header") {
        "header_mutation"
    } else if reason.contains("sequence") || reason.contains("result") {
        "protocol"
    } else {
        "service"
    }
}
