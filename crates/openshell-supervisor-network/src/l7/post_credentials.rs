// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Restricted in-process request middleware that runs after credential
//! resolution. External middleware can never enter this phase.

use std::io::SeekFrom;

use miette::{IntoDiagnostic as _, Result, miette};
use openshell_core::secrets::SecretResolver;
use openshell_supervisor_middleware_builtins::sigv4::{
    BodyFraming as SigV4BodyFraming, PayloadMode as SigV4PayloadMode, RequestedPayloadMode,
    SigV4Middleware, SigningCredentials, SigningTarget,
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeekExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::l7::middleware::RequestBodySpool;
use crate::l7::provider::{BodyLength, L7Request};
use crate::opa::PolicyGenerationGuard;

/// A trusted built-in synthesized from endpoint policy. It is deliberately not
/// representable by an operator-run middleware registration.
#[derive(Clone, Copy, Debug)]
pub enum PostCredentialsMiddleware<'a> {
    SigV4 {
        requested_mode: RequestedPayloadMode,
        service: &'a str,
        region: &'a str,
        host: &'a str,
        port: u16,
    },
}

/// Result of the post-credentials stage. A complete request already contains
/// its body; a signed head leaves normalized body relay to the HTTP owner.
pub enum PostCredentialsOutput {
    Complete {
        request: Vec<u8>,
        payload_mode: SigV4PayloadMode,
    },
    Head {
        headers: Vec<u8>,
        payload_mode: SigV4PayloadMode,
    },
}

impl<'a> PostCredentialsMiddleware<'a> {
    pub(crate) fn from_endpoint(
        signing: crate::l7::CredentialSigning,
        service: &'a str,
        region: &'a str,
        host: &'a str,
        port: u16,
    ) -> Option<Self> {
        let requested_mode = match signing {
            crate::l7::CredentialSigning::None => return None,
            crate::l7::CredentialSigning::SigV4 => RequestedPayloadMode::Auto,
            crate::l7::CredentialSigning::SigV4Body => RequestedPayloadMode::SignBody,
            crate::l7::CredentialSigning::SigV4NoBody => RequestedPayloadMode::UnsignedPayload,
        };
        Some(Self::SigV4 {
            requested_mode,
            service,
            region,
            host,
            port,
        })
    }

    /// Remove caller-provided authorization fields before placeholder
    /// rewriting. The trusted stage regenerates them after credentials resolve.
    pub(crate) fn strip_caller_authorization(self, raw_headers: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::SigV4 { .. } => SigV4Middleware::strip_existing_auth(raw_headers),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn evaluate<C>(
        self,
        request: &L7Request,
        original_headers: &str,
        rewritten_headers: &[u8],
        client: &mut C,
        prepared_body: Option<&mut RequestBodySpool>,
        resolver: Option<&SecretResolver>,
        generation_guard: Option<&PolicyGenerationGuard>,
    ) -> Result<PostCredentialsOutput>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            Self::SigV4 {
                requested_mode,
                service,
                region,
                host,
                ..
            } => {
                let resolver = resolver.ok_or_else(|| {
                    miette::Report::new(super::rest::CredentialUnavailableError::new(
                        "SigV4 signing configured but no secret resolver available",
                    ))
                })?;
                let access_key = resolver
                    .resolve_current_env_key_checked("AWS_ACCESS_KEY_ID", "sigv4")
                    .map_err(miette::Report::new)?;
                let secret_key = resolver
                    .resolve_current_env_key_checked("AWS_SECRET_ACCESS_KEY", "sigv4")
                    .map_err(miette::Report::new)?;
                let session_token = resolver
                    .resolve_current_env_key_checked("AWS_SESSION_TOKEN", "sigv4")
                    .map_err(miette::Report::new)?;
                let (Some(access_key), Some(secret_key)) = (access_key, secret_key) else {
                    return Err(miette::Report::new(
                        super::rest::CredentialUnavailableError::new(
                            "SigV4 signing configured but AWS credentials not found in provider",
                        ),
                    ));
                };

                if service.is_empty() {
                    return Err(miette!(
                        "SigV4 signing configured but signing_service not set in policy"
                    ));
                }
                let resolved_region = if region.is_empty() {
                    openshell_supervisor_middleware_builtins::sigv4::extract_aws_region(host)
                        .ok_or_else(|| {
                            miette!(
                                "SigV4 signing: cannot extract AWS region from hostname \
                                 '{host}'; set signing_region in the policy endpoint"
                            )
                        })?
                } else {
                    region.to_string()
                };

                let framing = sigv4_body_framing(request.body_length);
                let payload_mode =
                    openshell_supervisor_middleware_builtins::sigv4::resolve_payload_mode(
                        requested_mode,
                        original_headers,
                        framing,
                    )?;
                let target = SigningTarget {
                    host,
                    region: &resolved_region,
                    service,
                };
                let credentials = SigningCredentials {
                    access_key,
                    secret_key,
                    session_token,
                };

                if payload_mode == SigV4PayloadMode::SignBody {
                    if matches!(request.body_length, BodyLength::Chunked) {
                        return Err(miette!(
                            "SigV4 body signing requires Content-Length; chunked transfer \
                             encoding is not supported in this mode"
                        ));
                    }
                    let body =
                        collect_body_for_signing(request, client, prepared_body, generation_guard)
                            .await?;
                    let mut complete = Vec::with_capacity(rewritten_headers.len() + body.len());
                    complete.extend_from_slice(rewritten_headers);
                    complete.extend_from_slice(&body);
                    let request = SigV4Middleware::sign_body(&complete, target, credentials)?;
                    Ok(PostCredentialsOutput::Complete {
                        request,
                        payload_mode,
                    })
                } else {
                    let headers = SigV4Middleware::sign_headers(
                        rewritten_headers,
                        target,
                        credentials,
                        payload_mode,
                    )?;
                    Ok(PostCredentialsOutput::Head {
                        headers,
                        payload_mode,
                    })
                }
            }
        }
    }

    pub(crate) fn emit_success(self, payload_mode: SigV4PayloadMode) {
        match self {
            Self::SigV4 {
                service,
                region,
                host,
                port,
                ..
            } => {
                let resolved_region = if region.is_empty() {
                    openshell_supervisor_middleware_builtins::sigv4::extract_aws_region(host)
                        .unwrap_or_else(|| "unknown".into())
                } else {
                    region.to_string()
                };
                let event = openshell_ocsf::NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(openshell_ocsf::ActivityId::Traffic)
                    .action(openshell_ocsf::ActionId::Allowed)
                    .disposition(openshell_ocsf::DispositionId::Allowed)
                    .severity(openshell_ocsf::SeverityId::Informational)
                    .status(openshell_ocsf::StatusId::Success)
                    .dst_endpoint(openshell_ocsf::Endpoint::from_domain(host, port))
                    .message(format!(
                        "openshell/sigv4 signed {host}:{port} service={service} \
                     region={resolved_region} mode={payload_mode}"
                    ))
                    .build();
                openshell_ocsf::ocsf_emit!(event);
            }
        }
    }
}

fn sigv4_body_framing(body_length: BodyLength) -> SigV4BodyFraming {
    match body_length {
        BodyLength::None => SigV4BodyFraming::None,
        BodyLength::ContentLength(_) => SigV4BodyFraming::ContentLength,
        BodyLength::Chunked => SigV4BodyFraming::Chunked,
    }
}

async fn collect_body_for_signing<C>(
    request: &L7Request,
    client: &mut C,
    prepared_body: Option<&mut RequestBodySpool>,
    generation_guard: Option<&PolicyGenerationGuard>,
) -> Result<Vec<u8>>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    use openshell_supervisor_middleware_builtins::sigv4::MAX_BODY_BYTES;

    if let Some(body) = prepared_body {
        if body.len > MAX_BODY_BYTES as u64 {
            return Err(miette!(
                "SigV4 body signing buffers at most {MAX_BODY_BYTES} bytes"
            ));
        }
        if !body.trailers.is_empty() {
            return Err(miette!(
                "SigV4 body signing does not support request trailers"
            ));
        }
        body.file.seek(SeekFrom::Start(0)).await.into_diagnostic()?;
        let capacity = usize::try_from(body.len)
            .map_err(|_| miette!("SigV4 middleware body does not fit addressable memory"))?;
        let mut bytes = Vec::with_capacity(capacity);
        body.file.read_to_end(&mut bytes).await.into_diagnostic()?;
        if bytes.len() as u64 != body.len {
            return Err(miette!("middleware request spool ended early"));
        }
        return Ok(bytes);
    }

    if has_expect_continue(original_header_text(request)?) {
        client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }

    let header_end = request_header_end(request);
    let overflow = &request.raw_header[header_end..];
    match request.body_length {
        BodyLength::None => {
            if !overflow.is_empty() {
                return Err(miette!("bodyless SigV4 request contains read-ahead bytes"));
            }
            Ok(Vec::new())
        }
        BodyLength::ContentLength(body_len) => {
            if body_len > MAX_BODY_BYTES as u64 {
                return Err(miette!(
                    "SigV4 body signing buffers at most {MAX_BODY_BYTES} bytes"
                ));
            }
            if overflow.len() as u64 > body_len {
                return Err(miette!(
                    "SigV4 request read-ahead exceeds its declared Content-Length"
                ));
            }
            let body_len = usize::try_from(body_len)
                .map_err(|_| miette!("SigV4 request body does not fit addressable memory"))?;
            let mut body = Vec::with_capacity(body_len);
            body.extend_from_slice(overflow);
            let remaining = body_len - overflow.len();
            if remaining > 0 {
                let start = body.len();
                body.resize(body_len, 0);
                client
                    .read_exact(&mut body[start..])
                    .await
                    .into_diagnostic()?;
            }
            if let Some(guard) = generation_guard {
                guard.ensure_current()?;
            }
            Ok(body)
        }
        BodyLength::Chunked => Err(miette!(
            "SigV4 body signing requires Content-Length; chunked transfer encoding is not supported"
        )),
    }
}

fn request_header_end(request: &L7Request) -> usize {
    request
        .raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(request.raw_header.len(), |position| position + 4)
}

fn original_header_text(request: &L7Request) -> Result<&str> {
    std::str::from_utf8(&request.raw_header[..request_header_end(request)])
        .map_err(|_| miette!("SigV4 request headers are not valid UTF-8"))
}

fn has_expect_continue(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("expect")
                && value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesizes_only_configured_post_credentials_middleware() {
        assert!(
            PostCredentialsMiddleware::from_endpoint(
                crate::l7::CredentialSigning::None,
                "",
                "",
                "example.com",
                443,
            )
            .is_none()
        );
        assert!(matches!(
            PostCredentialsMiddleware::from_endpoint(
                crate::l7::CredentialSigning::SigV4NoBody,
                "s3",
                "us-east-1",
                "s3.us-east-1.amazonaws.com",
                443,
            ),
            Some(PostCredentialsMiddleware::SigV4 {
                requested_mode: RequestedPayloadMode::UnsignedPayload,
                ..
            })
        ));
    }
}
