// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Upstream I/O wrapper that charges bytes to the current attribution.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::ledger::TokenBucket;
use super::table::UsageEntry;

/// Where bytes of the current connection or request are charged.
#[derive(Debug)]
pub struct Attribution {
    pub entry: Arc<UsageEntry>,
    pub bytes_out: Vec<Arc<TokenBucket>>,
    pub bytes_in: Vec<Arc<TokenBucket>>,
}

impl Attribution {
    fn charge_out(&self, amount: u64) {
        self.entry.add_bytes_out(amount);
        for bucket in &self.bytes_out {
            bucket.debit(amount);
        }
    }

    fn charge_in(&self, amount: u64) {
        self.entry.add_bytes_in(amount);
        for bucket in &self.bytes_in {
            bucket.debit(amount);
        }
    }
}

/// Status line prefix length: `HTTP/1.1 200`.
const STATUS_LINE_PREFIX: usize = 12;

/// Swappable attribution for one upstream connection, plus its totals.
#[derive(Debug)]
pub struct AttributionCell {
    current: RwLock<Arc<Attribution>>,
    awaiting_status: AtomicBool,
    status_prefix: Mutex<Vec<u8>>,
    total_out: AtomicU64,
    total_in: AtomicU64,
}

impl AttributionCell {
    pub fn new(attribution: Arc<Attribution>) -> Arc<Self> {
        Arc::new(Self {
            current: RwLock::new(attribution),
            awaiting_status: AtomicBool::new(false),
            status_prefix: Mutex::new(Vec::new()),
            total_out: AtomicU64::new(0),
            total_in: AtomicU64::new(0),
        })
    }

    fn current(&self) -> Arc<Attribution> {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Charge the bytes that follow to a new request, and read the HTTP
    /// status of its response from the next upstream bytes.
    pub fn switch_to_request(&self, attribution: Arc<Attribution>) {
        *self
            .current
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = attribution;
        self.status_prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.awaiting_status.store(true, Ordering::Release);
    }

    /// Bytes sent and received over the connection lifetime.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.total_out.load(Ordering::Acquire),
            self.total_in.load(Ordering::Acquire),
        )
    }

    fn on_write(&self, amount: usize) {
        let amount = amount as u64;
        self.total_out.fetch_add(amount, Ordering::AcqRel);
        self.current().charge_out(amount);
    }

    fn on_read(&self, bytes: &[u8]) {
        let amount = bytes.len() as u64;
        self.total_in.fetch_add(amount, Ordering::AcqRel);
        let attribution = self.current();
        attribution.charge_in(amount);
        if self.awaiting_status.load(Ordering::Acquire) {
            self.observe_status(&attribution, bytes);
        }
    }

    fn observe_status(&self, attribution: &Attribution, bytes: &[u8]) {
        let mut prefix = self
            .status_prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let needed = STATUS_LINE_PREFIX.saturating_sub(prefix.len());
        prefix.extend_from_slice(&bytes[..bytes.len().min(needed)]);
        if prefix.len() < STATUS_LINE_PREFIX {
            return;
        }
        self.awaiting_status.store(false, Ordering::Release);
        if let Some(status) = parse_status(&prefix) {
            attribution.entry.record_status(status);
        }
    }
}

fn parse_status(prefix: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(prefix).ok()?;
    let rest = line.strip_prefix("HTTP/1.")?;
    let code = rest.get(2..5)?;
    code.parse().ok()
}

/// Upstream stream wrapper that charges every copied byte.
pub struct CountingStream<U> {
    inner: U,
    cell: Arc<AttributionCell>,
}

impl<U> CountingStream<U> {
    pub fn new(inner: U, cell: Arc<AttributionCell>) -> Self {
        Self { inner, cell }
    }

    /// Return the wrapped stream, for example to establish upstream TLS and
    /// wrap the TLS session instead.
    pub fn into_inner(self) -> U {
        self.inner
    }
}

impl<U: AsyncRead + Unpin> AsyncRead for CountingStream<U> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.cell.on_read(&buf.filled()[before..]);
        }
        result
    }
}

impl<U: AsyncWrite + Unpin> AsyncWrite for CountingStream<U> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            this.cell.on_write(written);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_status_prefix() {
        assert_eq!(parse_status(b"HTTP/1.1 200"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 429"), Some(429));
        assert_eq!(parse_status(b"SSH-2.0-Open"), None);
    }
}
