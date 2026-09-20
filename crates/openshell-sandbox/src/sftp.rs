// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust SFTP server launched through the workload boundary.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use miette::{IntoDiagnostic as _, Result};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode,
};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

struct OpenDirectory {
    entries: std::fs::ReadDir,
}

const MAX_HANDLES: usize = 256;
const MAX_READ_SIZE: usize = 256 * 1024;

struct SftpHandler {
    root: PathBuf,
    files: HashMap<String, tokio::fs::File>,
    directories: HashMap<String, OpenDirectory>,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for SftpHandler {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl SftpHandler {
    fn new_with_root(root: PathBuf, done: tokio::sync::oneshot::Sender<()>) -> io::Result<Self> {
        Ok(Self {
            root: std::fs::canonicalize(root)?,
            files: HashMap::new(),
            directories: HashMap::new(),
            done: Some(done),
        })
    }

    fn relative(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let path = Path::new(path);
        let path = if path.is_absolute() && path.starts_with(&self.root) {
            path.strip_prefix(&self.root)
                .map_err(|_| StatusCode::PermissionDenied)?
        } else {
            path
        };
        let mut relative = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(value) => relative.push(value),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(StatusCode::PermissionDenied);
                }
            }
        }
        Ok(relative)
    }

    fn existing_path(&self, path: &str, follow_leaf: bool) -> Result<PathBuf, StatusCode> {
        let candidate = self.root.join(self.relative(path)?);
        let resolved = if follow_leaf {
            std::fs::canonicalize(&candidate).map_err(status_code)?
        } else {
            let parent = candidate.parent().ok_or(StatusCode::PermissionDenied)?;
            let parent = std::fs::canonicalize(parent).map_err(status_code)?;
            parent.join(candidate.file_name().ok_or(StatusCode::PermissionDenied)?)
        };
        if !resolved.starts_with(&self.root) {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(resolved)
    }

    fn create_path(&self, path: &str) -> Result<PathBuf, StatusCode> {
        let candidate = self.root.join(self.relative(path)?);
        let parent = candidate.parent().ok_or(StatusCode::PermissionDenied)?;
        let parent = std::fs::canonicalize(parent).map_err(status_code)?;
        if !parent.starts_with(&self.root) {
            return Err(StatusCode::PermissionDenied);
        }
        Ok(parent.join(candidate.file_name().ok_or(StatusCode::PermissionDenied)?))
    }

    fn handle() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn reserve_handle(&self) -> Result<(), StatusCode> {
        if self.files.len() + self.directories.len() >= MAX_HANDLES {
            Err(StatusCode::Failure)
        } else {
            Ok(())
        }
    }
}

fn status_code(error: io::Error) -> StatusCode {
    match error.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: "en-US".to_string(),
    }
}

fn attributes(metadata: &std::fs::Metadata) -> FileAttributes {
    let mut attrs = FileAttributes::from(metadata);
    if metadata.file_type().is_symlink() {
        attrs.set_regular(false);
        attrs.set_symlink(true);
    }
    attrs
}

impl russh_sftp::server::Handler for SftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.reserve_handle()?;
        let path = if pflags.contains(OpenFlags::CREATE) {
            self.create_path(&filename)?
        } else {
            self.existing_path(&filename, true)?
        };
        let mut options: std::fs::OpenOptions = pflags.into();
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path).map_err(status_code)?;
        let handle = Self::handle();
        self.files
            .insert(handle.clone(), tokio::fs::File::from_std(file));
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        if self.files.remove(&handle).is_none() && self.directories.remove(&handle).is_none() {
            return Err(StatusCode::Failure);
        }
        Ok(ok(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(io::SeekFrom::Start(offset))
            .await
            .map_err(status_code)?;
        let requested = usize::try_from(len).map_err(|_| StatusCode::BadMessage)?;
        let mut data = vec![0; requested.min(MAX_READ_SIZE)];
        let count = file.read(&mut data).await.map_err(status_code)?;
        if count == 0 {
            return Err(StatusCode::Eof);
        }
        data.truncate(count);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        file.seek(io::SeekFrom::Start(offset))
            .await
            .map_err(status_code)?;
        file.write_all(&data).await.map_err(status_code)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.existing_path(&path, false)?;
        let metadata = std::fs::symlink_metadata(path).map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&metadata),
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let path = self.existing_path(&path, true)?;
        let metadata = std::fs::metadata(path).map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&metadata),
        })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let metadata = self
            .files
            .get(&handle)
            .ok_or(StatusCode::Failure)?
            .metadata()
            .await
            .map_err(status_code)?;
        Ok(Attrs {
            id,
            attrs: attributes(&metadata),
        })
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let file = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if let Some(size) = attrs.size {
            file.set_len(size).await.map_err(status_code)?;
        }
        if let Some(mode) = attrs.permissions {
            file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))
                .await
                .map_err(status_code)?;
        }
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.reserve_handle()?;
        let path = self.existing_path(&path, true)?;
        let entries = std::fs::read_dir(path).map_err(status_code)?;
        let handle = Self::handle();
        self.directories
            .insert(handle.clone(), OpenDirectory { entries });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let directory = self
            .directories
            .get_mut(&handle)
            .ok_or(StatusCode::Failure)?;
        let mut files = Vec::with_capacity(128);
        for entry in directory.entries.by_ref().take(128) {
            let entry = entry.map_err(status_code)?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(status_code)?;
            files.push(File::new(
                entry.file_name().to_string_lossy(),
                attributes(&metadata),
            ));
        }
        if files.is_empty() {
            Err(StatusCode::Eof)
        } else {
            Ok(Name { id, files })
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        let path = self.existing_path(&filename, false)?;
        std::fs::remove_file(path).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.create_path(&path)?;
        std::fs::create_dir(&path).map_err(status_code)?;
        if let Some(mode) = attrs.permissions {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))
                .map_err(status_code)?;
        }
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        std::fs::remove_dir(self.existing_path(&path, true)?).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let resolved = self.existing_path(&path, true)?;
        let relative = resolved
            .strip_prefix(&self.root)
            .map_err(|_| StatusCode::PermissionDenied)?;
        Ok(Name {
            id,
            files: vec![File::dummy(format!("/{}", relative.display()))],
        })
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let old = self.existing_path(&oldpath, false)?;
        let new = self.create_path(&newpath)?;
        std::fs::rename(old, new).map_err(status_code)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = std::fs::read_link(self.existing_path(&path, false)?).map_err(status_code)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target.to_string_lossy())],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        std::os::unix::fs::symlink(targetpath, self.create_path(&linkpath)?)
            .map_err(status_code)?;
        Ok(ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = self.existing_path(&path, true)?;
        if let Some(size) = attrs.size {
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(status_code)?
                .set_len(size)
                .map_err(status_code)?;
        }
        if let Some(mode) = attrs.permissions {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777))
                .map_err(status_code)?;
        }
        Ok(ok(id))
    }
}

pub fn run() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .into_diagnostic()?;
    runtime.block_on(async {
        let stream = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        serve(stream, std::env::current_dir().into_diagnostic()?).await
    })
}

pub(crate) async fn serve<S>(stream: S, root: PathBuf) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let handler = SftpHandler::new_with_root(root, done_tx).into_diagnostic()?;
    russh_sftp::server::run_with_config(
        stream,
        handler,
        russh_sftp::server::Config {
            max_client_packet_len: 1024 * 1024,
        },
    )
    .await;
    let _ = done_rx.await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::client::SftpSession;

    #[tokio::test]
    async fn adapter_round_trips_files_and_rejects_parent_traversal() {
        let root = tempfile::tempdir().unwrap();
        let (done_tx, _done_rx) = tokio::sync::oneshot::channel();
        let handler = SftpHandler::new_with_root(root.path().to_path_buf(), done_tx).unwrap();
        let (client_stream, server_stream) = tokio::io::duplex(1024 * 1024);
        russh_sftp::server::run_with_config(
            server_stream,
            handler,
            russh_sftp::server::Config {
                max_client_packet_len: 1024 * 1024,
            },
        )
        .await;
        let client = SftpSession::new(client_stream).await.unwrap();
        let mut file = client
            .open_with_flags(
                "hello.txt",
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
            )
            .await
            .unwrap();
        file.write_all(b"hello from sftp").await.unwrap();
        file.rewind().await.unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).await.unwrap();
        assert_eq!(contents, "hello from sftp");
        assert!(client.metadata("../outside").await.is_err());
    }
}
