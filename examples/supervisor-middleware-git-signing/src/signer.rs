// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const SHA1_HEX_LEN: usize = 40;
const ZERO_SHA1: &str = "0000000000000000000000000000000000000000";
const MAX_RECEIVE_PACK_PREFIX_BYTES: usize = 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 64 * 1024 * 1024;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub struct GitSigner {
    signing_key: PathBuf,
    upstream_override: Option<String>,
}

pub struct SignedPush {
    pub body: File,
    pub body_len: u64,
    pub signed_commits: u32,
}

#[derive(Clone)]
pub struct SignControl {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl SignControl {
    pub fn new(cancelled: Arc<AtomicBool>, deadline: Instant) -> Self {
        Self {
            cancelled,
            deadline,
        }
    }

    fn check(&self) -> Result<(), SignError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SignError::cancelled());
        }
        if Instant::now() >= self.deadline {
            return Err(SignError::timed_out());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SignError {
    message: String,
    kind: SignErrorKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignErrorKind {
    InvalidRequest,
    Cancelled,
    TimedOut,
}

impl SignError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: SignErrorKind::InvalidRequest,
        }
    }

    fn cancelled() -> Self {
        Self {
            message: "Git signing was cancelled".into(),
            kind: SignErrorKind::Cancelled,
        }
    }

    fn timed_out() -> Self {
        Self {
            message: "Git signing exceeded its deadline".into(),
            kind: SignErrorKind::TimedOut,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.kind == SignErrorKind::Cancelled
    }

    pub fn is_timed_out(&self) -> bool {
        self.kind == SignErrorKind::TimedOut
    }

    pub fn public_message(&self) -> &'static str {
        "outgoing Git push could not be signed"
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SignError {}

impl GitSigner {
    pub fn new(signing_key: PathBuf) -> Result<Self, String> {
        if !signing_key.is_file() {
            return Err("the signing key must name a readable file".into());
        }
        Ok(Self {
            signing_key,
            upstream_override: None,
        })
    }

    #[cfg(test)]
    fn new_with_upstream_override(
        signing_key: PathBuf,
        upstream_override: String,
    ) -> Result<Self, String> {
        let mut signer = Self::new(signing_key)?;
        signer.upstream_override = Some(upstream_override);
        Ok(signer)
    }

    pub fn sign_receive_pack(
        &self,
        mut body: File,
        upstream_url: Option<&str>,
        control: &SignControl,
    ) -> Result<SignedPush, SignError> {
        control.check()?;
        let mut parsed = ReceivePackRequest::parse_file(&mut body)?;
        if parsed.updates.is_empty() {
            return Err(SignError::new(
                "receive-pack request contains no ref updates",
            ));
        }

        let workspace = TempDir::new().map_err(|error| SignError::new(error.to_string()))?;
        let repo = workspace.path().join("objects.git");
        run_git_controlled(
            None,
            &["init", "--bare", repo_string(&repo)?],
            None,
            control,
        )?;
        if let Some(upstream_url) = self.upstream_override.as_deref().or(upstream_url) {
            hydrate_upstream(&repo, upstream_url, &parsed.updates, control)?;
        }
        body.seek(SeekFrom::Start(parsed.pack_offset))
            .map_err(|error| SignError::new(error.to_string()))?;
        run_git_file_input(
            Some(&repo),
            &["index-pack", "--stdin", "--fix-thin"],
            body,
            control,
        )?;

        let mut commit_ids = HashSet::new();
        for update in &parsed.updates {
            if update.new_oid == ZERO_SHA1 {
                continue;
            }
            control.check()?;
            let output = run_git_controlled(
                Some(&repo),
                &["rev-list", &update.new_oid, "--not", "--all"],
                None,
                control,
            )?;
            let output = String::from_utf8(output)
                .map_err(|_| SignError::new("git returned a non-UTF-8 commit list"))?;
            commit_ids.extend(output.lines().map(str::to_string));
        }
        let mut rewriter = CommitRewriter {
            repo: &repo,
            signing_key: &self.signing_key,
            commit_ids,
            rewritten: HashMap::new(),
            active: HashSet::new(),
            signed_count: 0,
            workspace: workspace.path(),
            control,
        };

        for update in &mut parsed.updates {
            if update.new_oid == ZERO_SHA1 {
                continue;
            }
            if !update.ref_name.starts_with("refs/heads/") {
                return Err(SignError::new(
                    "prototype supports direct branch updates only",
                ));
            }
            if !rewriter.commit_ids.contains(&update.new_oid) {
                return Err(SignError::new(
                    "branch tip commit is not self-contained in the push pack",
                ));
            }
            update.new_oid = rewriter.rewrite(&update.new_oid)?;
        }

        if rewriter.signed_count == 0 {
            return Err(SignError::new(
                "receive-pack request contains no commits to sign",
            ));
        }

        let base_oids = list_ref_oids(&repo, "refs/middleware", control)?;
        let mut revisions = parsed
            .updates
            .iter()
            .filter(|update| update.new_oid != ZERO_SHA1)
            .map(|update| update.new_oid.clone())
            .collect::<Vec<_>>();
        revisions.extend(base_oids.into_iter().map(|oid| format!("^{oid}")));
        let revision_input = revisions.join("\n") + "\n";
        let mut prefix = parsed.prefix;
        for update in &parsed.updates {
            prefix[update.new_oid_range.clone()].copy_from_slice(update.new_oid.as_bytes());
        }
        let mut result = tempfile::tempfile().map_err(|error| SignError::new(error.to_string()))?;
        result
            .write_all(&prefix)
            .map_err(|error| SignError::new(error.to_string()))?;
        run_git_to_file(
            Some(&repo),
            &["pack-objects", "--stdout", "--revs", "--thin"],
            Some(revision_input.as_bytes()),
            &mut result,
            control,
        )?;
        let body_len = result
            .metadata()
            .map_err(|error| SignError::new(error.to_string()))?
            .len();
        result
            .seek(SeekFrom::Start(0))
            .map_err(|error| SignError::new(error.to_string()))?;
        Ok(SignedPush {
            body: result,
            body_len,
            signed_commits: rewriter.signed_count,
        })
    }
}

struct ReceivePackRequest {
    prefix: Vec<u8>,
    pack_offset: u64,
    updates: Vec<RefUpdate>,
}

struct RefUpdate {
    old_oid: String,
    new_oid: String,
    ref_name: String,
    new_oid_range: std::ops::Range<usize>,
}

impl ReceivePackRequest {
    fn parse_file(body: &mut File) -> Result<Self, SignError> {
        body.seek(SeekFrom::Start(0))
            .map_err(|error| SignError::new(error.to_string()))?;
        let mut prefix = Vec::new();
        let mut updates = Vec::new();
        let mut offset = 0;
        let mut command_section = true;
        let pack_offset = loop {
            let mut marker = [0u8; 4];
            body.read_exact(&mut marker)
                .map_err(|_| SignError::new("receive-pack request has no packfile"))?;
            if !command_section && marker == *b"PACK" {
                body.seek(SeekFrom::Current(-4))
                    .map_err(|error| SignError::new(error.to_string()))?;
                break offset as u64;
            }
            let length = parse_pkt_length(&marker)?;
            prefix.extend_from_slice(&marker);
            if prefix.len() > MAX_RECEIVE_PACK_PREFIX_BYTES {
                return Err(SignError::new("receive-pack command prefix is too large"));
            }
            if length == 0 {
                offset += 4;
                command_section = false;
                continue;
            }
            if length < 4 {
                return Err(SignError::new("invalid receive-pack pkt-line length"));
            }
            let payload_start = offset + 4;
            let mut payload = vec![0; length - 4];
            body.read_exact(&mut payload)
                .map_err(|_| SignError::new("truncated receive-pack pkt-line"))?;
            prefix.extend_from_slice(&payload);
            if prefix.len() > MAX_RECEIVE_PACK_PREFIX_BYTES {
                return Err(SignError::new("receive-pack command prefix is too large"));
            }
            if !command_section {
                // Push options, when negotiated, are pkt-lines between the
                // command flush and the packfile. Preserve them unchanged.
                offset += length;
                continue;
            }
            let command = payload.split(|byte| *byte == 0).next().unwrap_or(&payload);
            let command = command.strip_suffix(b"\n").unwrap_or(command);
            let first_space = command
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(|| SignError::new("invalid receive-pack ref command"))?;
            let second_space = command[first_space + 1..]
                .iter()
                .position(|byte| *byte == b' ')
                .map(|index| first_space + 1 + index)
                .ok_or_else(|| SignError::new("invalid receive-pack ref command"))?;
            if first_space != SHA1_HEX_LEN || second_space - first_space - 1 != SHA1_HEX_LEN {
                return Err(SignError::new(
                    "prototype supports SHA-1 Git repositories only",
                ));
            }
            let new_start = payload_start + first_space + 1;
            let old_oid = ascii_oid(&prefix[payload_start..payload_start + SHA1_HEX_LEN])?;
            let new_oid = ascii_oid(&prefix[new_start..new_start + SHA1_HEX_LEN])?;
            let ref_name = std::str::from_utf8(&command[second_space + 1..])
                .map_err(|_| SignError::new("receive-pack ref name is not UTF-8"))?
                .to_string();
            updates.push(RefUpdate {
                old_oid,
                new_oid,
                ref_name,
                new_oid_range: new_start..new_start + SHA1_HEX_LEN,
            });
            offset += length;
        };

        Ok(Self {
            prefix,
            pack_offset,
            updates,
        })
    }
}

fn hydrate_upstream(
    repo: &Path,
    upstream_url: &str,
    updates: &[RefUpdate],
    control: &SignControl,
) -> Result<(), SignError> {
    run_git_controlled(
        Some(repo),
        &[
            "-c",
            "credential.interactive=false",
            "fetch",
            "--no-tags",
            "--depth=1",
            upstream_url,
            "+HEAD:refs/middleware/upstream-head",
        ],
        None,
        control,
    )?;
    for (index, old_oid) in updates
        .iter()
        .map(|update| update.old_oid.as_str())
        .filter(|oid| *oid != ZERO_SHA1)
        .collect::<HashSet<_>>()
        .into_iter()
        .enumerate()
    {
        let destination = format!("+{old_oid}:refs/middleware/base-{index}");
        run_git_controlled(
            Some(repo),
            &[
                "-c",
                "credential.interactive=false",
                "fetch",
                "--no-tags",
                "--depth=1",
                upstream_url,
                &destination,
            ],
            None,
            control,
        )?;
    }
    Ok(())
}

fn list_ref_oids(
    repo: &Path,
    prefix: &str,
    control: &SignControl,
) -> Result<Vec<String>, SignError> {
    let output = run_git_controlled(
        Some(repo),
        &["for-each-ref", "--format=%(objectname)", prefix],
        None,
        control,
    )?;
    let output = String::from_utf8(output)
        .map_err(|_| SignError::new("git returned a non-UTF-8 ref list"))?;
    Ok(output.lines().map(str::to_string).collect())
}

fn parse_pkt_length(bytes: &[u8]) -> Result<usize, SignError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| SignError::new("pkt-line length is not ASCII"))?;
    usize::from_str_radix(text, 16).map_err(|_| SignError::new("invalid pkt-line length"))
}

fn ascii_oid(bytes: &[u8]) -> Result<String, SignError> {
    if bytes.len() != SHA1_HEX_LEN || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(SignError::new("invalid SHA-1 object id"));
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| SignError::new("invalid SHA-1 object id"))
}

struct CommitRewriter<'a> {
    repo: &'a Path,
    signing_key: &'a Path,
    commit_ids: HashSet<String>,
    rewritten: HashMap<String, String>,
    active: HashSet<String>,
    signed_count: u32,
    workspace: &'a Path,
    control: &'a SignControl,
}

impl CommitRewriter<'_> {
    fn rewrite(&mut self, oid: &str) -> Result<String, SignError> {
        self.control.check()?;
        if let Some(rewritten) = self.rewritten.get(oid) {
            return Ok(rewritten.clone());
        }
        if !self.commit_ids.contains(oid) {
            return Ok(oid.to_string());
        }
        if !self.active.insert(oid.to_string()) {
            return Err(SignError::new("commit graph contains a cycle"));
        }

        let raw = run_git_controlled(
            Some(self.repo),
            &["cat-file", "commit", oid],
            None,
            self.control,
        )?;
        let parsed = ParsedCommit::parse(&raw)?;
        let mut parents = Vec::with_capacity(parsed.parents.len());
        for parent in &parsed.parents {
            parents.push(self.rewrite(parent)?);
        }
        let unsigned = parsed.unsigned_with_parents(&parents);
        let signature = self.sign_payload(oid, &unsigned)?;
        let signed = insert_signature(&unsigned, &signature)?;
        let new_oid = String::from_utf8(run_git_controlled(
            Some(self.repo),
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Some(&signed),
            self.control,
        )?)
        .map_err(|_| SignError::new("git returned a non-UTF-8 object id"))?
        .trim()
        .to_string();

        self.active.remove(oid);
        self.rewritten.insert(oid.to_string(), new_oid.clone());
        self.signed_count = self.signed_count.saturating_add(1);
        Ok(new_oid)
    }

    fn sign_payload(&self, oid: &str, payload: &[u8]) -> Result<Vec<u8>, SignError> {
        let payload_path = self.workspace.join(format!("commit-{oid}"));
        fs::write(&payload_path, payload).map_err(|error| SignError::new(error.to_string()))?;
        let mut command = Command::new("ssh-keygen");
        command
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(self.signing_key)
            .arg(&payload_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        run_command_controlled(command, None, "ssh-keygen", self.control)?;
        // ssh-keygen appends `.sig` to the input path.
        let signature_path = PathBuf::from(format!("{}.sig", payload_path.display()));
        fs::read(signature_path).map_err(|error| SignError::new(error.to_string()))
    }
}

struct ParsedCommit {
    headers: Vec<Header>,
    parents: Vec<String>,
    message: Vec<u8>,
}

struct Header {
    name: Vec<u8>,
    block: Vec<u8>,
}

impl ParsedCommit {
    fn parse(raw: &[u8]) -> Result<Self, SignError> {
        let separator = raw
            .windows(2)
            .position(|window| window == b"\n\n")
            .ok_or_else(|| SignError::new("commit object has no header separator"))?;
        let header_bytes = &raw[..separator];
        let mut headers: Vec<Header> = Vec::new();
        for line in header_bytes.split(|byte| *byte == b'\n') {
            if line.starts_with(b" ") {
                let previous = headers
                    .last_mut()
                    .ok_or_else(|| SignError::new("commit starts with a continuation header"))?;
                previous.block.push(b'\n');
                previous.block.extend_from_slice(line);
                continue;
            }
            let name_end = line
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(|| SignError::new("invalid commit header"))?;
            headers.push(Header {
                name: line[..name_end].to_vec(),
                block: line.to_vec(),
            });
        }
        let parents = headers
            .iter()
            .filter(|header| header.name == b"parent")
            .map(|header| ascii_oid(&header.block[b"parent ".len()..]))
            .collect::<Result<Vec<_>, _>>()?;
        if !headers.iter().any(|header| header.name == b"tree") {
            return Err(SignError::new("commit object has no tree"));
        }
        Ok(Self {
            headers,
            parents,
            message: raw[separator + 2..].to_vec(),
        })
    }

    fn unsigned_with_parents(&self, parents: &[String]) -> Vec<u8> {
        let mut result = Vec::new();
        let mut parent_index = 0;
        for header in &self.headers {
            if header.name == b"gpgsig" || header.name == b"gpgsig-sha256" {
                continue;
            }
            if header.name == b"parent" {
                result.extend_from_slice(b"parent ");
                result.extend_from_slice(parents[parent_index].as_bytes());
                parent_index += 1;
            } else {
                result.extend_from_slice(&header.block);
            }
            result.push(b'\n');
        }
        result.push(b'\n');
        result.extend_from_slice(&self.message);
        result
    }
}

fn insert_signature(unsigned: &[u8], signature: &[u8]) -> Result<Vec<u8>, SignError> {
    let separator = unsigned
        .windows(2)
        .position(|window| window == b"\n\n")
        .ok_or_else(|| SignError::new("unsigned commit has no header separator"))?;
    let signature = signature.strip_suffix(b"\n").unwrap_or(signature);
    let mut result = Vec::with_capacity(unsigned.len() + signature.len() + 16);
    result.extend_from_slice(&unsigned[..separator + 1]);
    for (index, line) in signature.split(|byte| *byte == b'\n').enumerate() {
        result.extend_from_slice(if index == 0 { b"gpgsig " } else { b" " });
        result.extend_from_slice(line);
        result.push(b'\n');
    }
    result.extend_from_slice(&unsigned[separator + 1..]);
    Ok(result)
}

fn repo_string(path: &Path) -> Result<&str, SignError> {
    path.to_str()
        .ok_or_else(|| SignError::new("temporary repository path is not UTF-8"))
}

fn run_git_controlled(
    repo: Option<&Path>,
    args: &[&str],
    input: Option<&[u8]>,
    control: &SignControl,
) -> Result<Vec<u8>, SignError> {
    let mut command = Command::new("git");
    if let Some(repo) = repo {
        command.arg("-C").arg(repo);
    }
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_command_controlled(
        command,
        input,
        args.first().copied().unwrap_or("command"),
        control,
    )
}

fn run_git_file_input(
    repo: Option<&Path>,
    args: &[&str],
    input: File,
    control: &SignControl,
) -> Result<Vec<u8>, SignError> {
    let mut command = Command::new("git");
    if let Some(repo) = repo {
        command.arg("-C").arg(repo);
    }
    command
        .args(args)
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_command_controlled(
        command,
        None,
        args.first().copied().unwrap_or("command"),
        control,
    )
}

fn run_git_to_file(
    repo: Option<&Path>,
    args: &[&str],
    input: Option<&[u8]>,
    output: &mut File,
    control: &SignControl,
) -> Result<(), SignError> {
    output
        .seek(SeekFrom::End(0))
        .map_err(|error| SignError::new(error.to_string()))?;
    let output_handle = output
        .try_clone()
        .map_err(|error| SignError::new(error.to_string()))?;
    let mut command = Command::new("git");
    if let Some(repo) = repo {
        command.arg("-C").arg(repo);
    }
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::from(output_handle))
        .stderr(Stdio::piped());
    run_command_controlled(
        command,
        input,
        args.first().copied().unwrap_or("command"),
        control,
    )?;
    Ok(())
}

fn run_command_controlled(
    mut command: Command,
    input: Option<&[u8]>,
    command_name: &str,
    control: &SignControl,
) -> Result<Vec<u8>, SignError> {
    control.check()?;
    let mut child = command
        .spawn()
        .map_err(|error| SignError::new(format!("could not run {command_name}: {error}")))?;
    let stdout = child.stdout.take().map(spawn_pipe_drain);
    let stderr = child.stderr.take().map(spawn_pipe_drain);
    if let Some(input) = input {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| SignError::new(format!("{command_name} stdin was unavailable")))?
            .write_all(input);
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SignError::new(error.to_string()));
        }
    }
    drop(child.stdin.take());

    let status = loop {
        if let Err(error) = control.check() {
            let _ = child.kill();
            let _ = child.wait();
            join_pipe(stdout)?;
            join_pipe(stderr)?;
            return Err(error);
        }
        match child
            .try_wait()
            .map_err(|error| SignError::new(error.to_string()))?
        {
            Some(status) => break status,
            None => std::thread::sleep(CHILD_POLL_INTERVAL),
        }
    };
    let stdout = join_pipe(stdout)?;
    let stderr = join_pipe(stderr)?;
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(SignError::new(format!(
            "{command_name} failed: {}",
            stderr.trim()
        )));
    }
    Ok(stdout)
}

type PipeDrain = std::thread::JoinHandle<std::io::Result<Vec<u8>>>;

fn spawn_pipe_drain<R>(mut pipe: R) -> PipeDrain
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            let read = pipe.read(&mut buffer)?;
            if read == 0 {
                return Ok(captured);
            }
            if captured.len() < MAX_CAPTURE_BYTES {
                let keep = read.min(MAX_CAPTURE_BYTES - captured.len());
                captured.extend_from_slice(&buffer[..keep]);
            }
        }
    })
}

fn join_pipe(drain: Option<PipeDrain>) -> Result<Vec<u8>, SignError> {
    drain.map_or_else(
        || Ok(Vec::new()),
        |drain| {
            drain
                .join()
                .map_err(|_| SignError::new("subprocess output worker failed"))?
                .map_err(|error| SignError::new(error.to_string()))
        },
    )
}

#[cfg(test)]
fn run_git(repo: Option<&Path>, args: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, SignError> {
    let control = SignControl::new(
        Arc::new(AtomicBool::new(false)),
        Instant::now() + Duration::from_secs(300),
    );
    run_git_controlled(repo, args, input, &control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        HttpHeader, HttpRequestBodyUnit, HttpRequestEvent, HttpRequestPreflight, HttpRequestTarget,
        HttpRequestTrailers, MiddlewareSessionEnd, RequestContext, http_request_body_result,
        http_request_body_unit, http_request_event, http_request_event_result,
    };
    use tokio_stream::StreamExt as _;

    #[cfg(unix)]
    #[test]
    fn cancellation_terminates_an_active_subprocess() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let control = SignControl::new(
            Arc::clone(&cancelled),
            Instant::now() + Duration::from_secs(30),
        );
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            let mut command = Command::new("sleep");
            command
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            run_command_controlled(command, None, "sleep", &control)
        });

        std::thread::sleep(Duration::from_millis(50));
        cancelled.store(true, Ordering::Release);
        let error = worker
            .join()
            .expect("subprocess worker must not panic")
            .expect_err("cancellation must terminate the subprocess");

        assert!(error.is_cancelled());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn signs_every_commit_and_rewrites_the_branch_tip() {
        let fixture = TempDir::new().unwrap();
        let source = fixture.path().join("source.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&source).unwrap()],
            None,
        )
        .unwrap();
        let large_blob = pseudo_random_bytes(5 * 1024 * 1024);
        let blob = object(&source, "blob", &large_blob);
        let tree_line = format!("100644 blob {blob}\tREADME.md\n");
        let tree = String::from_utf8(
            run_git(Some(&source), &["mktree"], Some(tree_line.as_bytes())).unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        let first = unsigned_commit(&source, &tree, None, "first");
        let second = unsigned_commit(&source, &tree, Some(&first), "second");
        let upstream_head = unsigned_commit(&source, &tree, None, "upstream");
        run_git(
            Some(&source),
            &["update-ref", "refs/heads/main", &upstream_head],
            None,
        )
        .unwrap();
        run_git(
            Some(&source),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            None,
        )
        .unwrap();
        let objects = format!("{blob}\n{tree}\n{first}\n{second}\n");
        let pack = run_git(
            Some(&source),
            &["pack-objects", "--stdout"],
            Some(objects.as_bytes()),
        )
        .unwrap();
        let body = receive_pack_body(&second, &pack);
        assert!(body.len() > 4 * 1024 * 1024);

        let key = fixture.path().join("signing-key");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(status.success());
        let signed = sign_through_owned_stream(&key, &source, &body).await;
        assert_eq!(signed.signed_commits, 2);

        let mut signed_file = file_with_bytes(&signed.body);
        let parsed = ReceivePackRequest::parse_file(&mut signed_file).unwrap();
        let new_tip = parsed.updates[0].new_oid.clone();
        assert_ne!(new_tip, second);
        let verify = fixture.path().join("verify.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&verify).unwrap()],
            None,
        )
        .unwrap();
        run_git(
            None,
            &[
                "receive-pack",
                "--stateless-rpc",
                repo_string(&verify).unwrap(),
            ],
            Some(&signed.body),
        )
        .unwrap();
        let received_tip = String::from_utf8(
            run_git(Some(&verify), &["rev-parse", "refs/heads/main"], None).unwrap(),
        )
        .unwrap();
        assert_eq!(received_tip.trim(), new_tip);
        let tip = run_git(Some(&verify), &["cat-file", "commit", &new_tip], None).unwrap();
        assert!(tip.windows(7).any(|window| window == b"gpgsig "));
        let tip = ParsedCommit::parse(&tip).unwrap();
        assert_eq!(tip.parents.len(), 1);
        assert_ne!(tip.parents[0], first);
        let parent = run_git(
            Some(&verify),
            &["cat-file", "commit", &tip.parents[0]],
            None,
        )
        .unwrap();
        assert!(parent.windows(7).any(|window| window == b"gpgsig "));

        let allowed = fixture.path().join("allowed-signers");
        let public_key = fs::read_to_string(key.with_extension("pub")).unwrap();
        fs::write(&allowed, format!("agent@example.com {}", public_key.trim())).unwrap();
        verify_commit(&verify, &allowed, &new_tip);
        verify_commit(&verify, &allowed, &tip.parents[0]);
    }

    struct CollectedSignedPush {
        body: Vec<u8>,
        signed_commits: u32,
    }

    async fn sign_through_owned_stream(
        key: &Path,
        upstream: &Path,
        body: &[u8],
    ) -> CollectedSignedPush {
        let signer = GitSigner::new_with_upstream_override(
            key.to_path_buf(),
            repo_string(upstream).unwrap().to_string(),
        )
        .unwrap();
        let mut middleware = crate::GitSigningMiddleware::new_for_test(key.to_path_buf()).unwrap();
        middleware.signer = std::sync::Arc::new(signer);
        let mut events = vec![Ok(HttpRequestEvent {
            event: Some(http_request_event::Event::Preflight(HttpRequestPreflight {
                context: Some(RequestContext {
                    request_id: "large-push".into(),
                    ..Default::default()
                }),
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
                permitted_body_modes: vec![
                    openshell_core::proto::HttpRequestBodyMode::OwnedStreamBytes as i32,
                ],
                max_payload_bytes: crate::MAX_UNIT_BYTES as u64,
                max_deferred_bytes: 16 * 1024 * 1024,
                ..Default::default()
            })),
        })];
        let mut final_input_sequence = 1u64;
        for (index, chunk) in body.chunks(crate::MAX_UNIT_BYTES).enumerate() {
            final_input_sequence = index as u64 + 1;
            events.push(Ok(HttpRequestEvent {
                event: Some(http_request_event::Event::Body(HttpRequestBodyUnit {
                    sequence: final_input_sequence,
                    payload: Some(http_request_body_unit::Payload::Data(chunk.to_vec())),
                    end_of_stream: false,
                })),
            }));
        }
        final_input_sequence += 1;
        events.push(Ok(HttpRequestEvent {
            event: Some(http_request_event::Event::Body(HttpRequestBodyUnit {
                sequence: final_input_sequence,
                payload: Some(http_request_body_unit::Payload::Data(Vec::new())),
                end_of_stream: true,
            })),
        }));
        events.push(Ok(HttpRequestEvent {
            event: Some(http_request_event::Event::Trailers(
                HttpRequestTrailers::default(),
            )),
        }));
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
        for sequence in 1..=final_input_sequence {
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

        let mut output = Vec::new();
        let mut next_output_sequence = 1u64;
        let signed_commits = loop {
            let result = results.next().await.unwrap().unwrap();
            match result.result {
                Some(http_request_event_result::Result::BodyOutput(unit)) => {
                    assert_eq!(unit.sequence, next_output_sequence);
                    next_output_sequence += 1;
                    output.extend_from_slice(&unit.data);
                }
                Some(http_request_event_result::Result::BodyFinalize(finalize)) => {
                    assert_eq!(finalize.through_input_sequence, final_input_sequence);
                    assert_eq!(finalize.through_output_sequence, next_output_sequence - 1);
                    break finalize.findings[0].count;
                }
                other => panic!("unexpected owned output result: {other:?}"),
            }
        };
        assert!(matches!(
            results.next().await.unwrap().unwrap().result,
            Some(http_request_event_result::Result::TrailersResult(_))
        ));
        assert!(results.next().await.is_none());
        CollectedSignedPush {
            body: output,
            signed_commits,
        }
    }

    #[test]
    fn rejects_non_branch_updates() {
        let payload = format!("{ZERO_SHA1} {ZERO_SHA1} refs/tags/v1\n");
        let length = payload.len() + 4;
        let mut body = format!("{length:04x}{payload}0000").into_bytes();
        body.extend_from_slice(b"PACK");
        let mut file = file_with_bytes(&body);
        let parsed = ReceivePackRequest::parse_file(&mut file).unwrap();
        assert_eq!(parsed.updates[0].ref_name, "refs/tags/v1");
    }

    #[test]
    fn resolves_a_thin_pack_from_the_upstream_repository() {
        let fixture = TempDir::new().unwrap();
        let source = fixture.path().join("source.git");
        run_git(
            None,
            &["init", "--bare", repo_string(&source).unwrap()],
            None,
        )
        .unwrap();
        let blob = object(&source, "blob", b"base\n");
        let tree_line = format!("100644 blob {blob}\tREADME.md\n");
        let tree = String::from_utf8(
            run_git(Some(&source), &["mktree"], Some(tree_line.as_bytes())).unwrap(),
        )
        .unwrap()
        .trim()
        .to_string();
        let base = unsigned_commit(&source, &tree, None, "base");
        run_git(
            Some(&source),
            &["update-ref", "refs/heads/main", &base],
            None,
        )
        .unwrap();
        run_git(
            Some(&source),
            &["symbolic-ref", "HEAD", "refs/heads/main"],
            None,
        )
        .unwrap();
        let tip = unsigned_commit(&source, &tree, Some(&base), "tip");
        let revisions = format!("{tip}\n^{base}\n");
        let pack = run_git(
            Some(&source),
            &["pack-objects", "--stdout", "--revs", "--thin"],
            Some(revisions.as_bytes()),
        )
        .unwrap();
        let body = receive_pack_body(&tip, &pack);

        let key = fixture.path().join("signing-key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        let signed = GitSigner::new(key)
            .unwrap()
            .sign_receive_pack(file_with_bytes(&body), source.to_str(), &test_control())
            .unwrap();
        assert_eq!(signed.signed_commits, 1);
    }

    fn file_with_bytes(bytes: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(bytes).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file
    }

    fn test_control() -> SignControl {
        SignControl::new(
            Arc::new(AtomicBool::new(false)),
            Instant::now() + Duration::from_secs(300),
        )
    }

    fn object(repo: &Path, kind: &str, body: &[u8]) -> String {
        String::from_utf8(
            run_git(
                Some(repo),
                &["hash-object", "-t", kind, "-w", "--stdin"],
                Some(body),
            )
            .unwrap(),
        )
        .unwrap()
        .trim()
        .to_string()
    }

    fn unsigned_commit(repo: &Path, tree: &str, parent: Option<&str>, subject: &str) -> String {
        let parent = parent.map_or(String::new(), |oid| format!("parent {oid}\n"));
        let raw = format!(
            "tree {tree}\n{parent}author Agent <agent@example.com> 1700000000 +0000\ncommitter Agent <agent@example.com> 1700000000 +0000\n\n{subject}\n"
        );
        object(repo, "commit", raw.as_bytes())
    }

    fn receive_pack_body(new_oid: &str, pack: &[u8]) -> Vec<u8> {
        let payload = format!(
            "{ZERO_SHA1} {new_oid} refs/heads/main\0 report-status side-band-64k object-format=sha1\n"
        );
        let length = payload.len() + 4;
        let mut body = format!("{length:04x}{payload}0000").into_bytes();
        body.extend_from_slice(pack);
        body
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x4d59_5df4_d0f3_3173_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    fn verify_commit(repo: &Path, allowed: &Path, oid: &str) {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "gpg.format=ssh", "-c"])
            .arg(format!("gpg.ssh.allowedSignersFile={}", allowed.display()))
            .args(["verify-commit", oid])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
