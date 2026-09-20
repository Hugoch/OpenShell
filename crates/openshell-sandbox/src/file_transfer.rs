// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workload-identity tar creation and extraction for native file transfer.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use miette::{Context as _, IntoDiagnostic as _, Result};
use rustix::fs::{
    AtFlags, Dir, Mode, OFlags, fchmod, mkdirat, openat, readlinkat, statat, symlinkat, unlinkat,
};

const SAFE_MODE_MASK: u32 = 0o777;
const SYMLINK_ESCAPE_ERROR: &str =
    "file-transfer source resolves to a path outside the sandbox workspace";

pub fn run(args: &[String]) -> Result<()> {
    let root = std::env::current_dir()
        .into_diagnostic()
        .wrap_err("resolve workload directory")?;
    run_at(
        args,
        &root,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
}

pub(crate) fn run_at<R: Read, W: Write>(
    args: &[String],
    root: &Path,
    reader: R,
    writer: W,
) -> Result<()> {
    let [direction, path] = args else {
        return Err(miette::miette!(
            "usage: openshell-sandbox file-transfer <upload|download> <RELATIVE_PATH>"
        ));
    };
    match direction.as_str() {
        "upload" => extract(reader, root, Path::new(path)),
        "download" => archive(writer, root, Path::new(path)),
        _ => Err(miette::miette!(
            "unknown file-transfer direction '{direction}'"
        )),
    }
}

fn components(path: &Path) -> Result<Vec<OsString>> {
    let mut result = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => result.push(value.to_os_string()),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(miette::miette!(
                    "file-transfer path must stay beneath the workload directory: {}",
                    path.display()
                ));
            }
        }
    }
    Ok(result)
}

fn safe_symlink_target(path: &Path) -> Result<()> {
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(miette::miette!(SYMLINK_ESCAPE_ERROR));
        }
    }
    Ok(())
}

fn target_components(root: &Path, path: &Path) -> Result<Vec<OsString>> {
    if path.is_absolute() {
        let relative = path.strip_prefix(root).map_err(|_| {
            miette::miette!(
                "file-transfer path must stay beneath the workload directory: {}",
                path.display()
            )
        })?;
        components(relative)
    } else {
        components(path)
    }
}

fn root_fd(root: &Path) -> Result<OwnedFd> {
    openat(
        rustix::fs::CWD,
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .into_diagnostic()
    .wrap_err("open workload directory")
}

fn open_dir_path(root: impl AsFd, path: &[OsString], create: bool) -> Result<OwnedFd> {
    let mut current = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .into_diagnostic()?;
    for component in path {
        if create {
            match mkdirat(&current, component, Mode::from_bits_truncate(0o755)) {
                Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                Err(error) => return Err(error).into_diagnostic(),
            }
        }
        current = openat(
            &current,
            component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            if matches!(error, rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) {
                miette::miette!(SYMLINK_ESCAPE_ERROR)
            } else {
                miette::miette!(
                    "open directory component {}: {error}",
                    component.to_string_lossy()
                )
            }
        })?;
    }
    Ok(current)
}

fn split_parent(path: &[OsString]) -> Result<(&[OsString], &OsStr)> {
    let Some((leaf, parent)) = path.split_last() else {
        return Err(miette::miette!("file-transfer archive entry path is empty"));
    };
    Ok((parent, leaf))
}

fn remove_non_directory(parent: impl AsFd, name: &OsStr) -> Result<()> {
    match unlinkat(parent, name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(error).into_diagnostic(),
    }
}

fn extract<R: Read>(reader: R, workload_root: &Path, destination: &Path) -> Result<()> {
    let root = root_fd(workload_root)?;
    let destination = target_components(workload_root, destination)?;
    open_dir_path(&root, &destination, true)?;
    let mut archive = tar::Archive::new(reader);
    let mut directory_modes = Vec::new();
    for item in archive.entries().into_diagnostic()? {
        let mut entry = item.into_diagnostic()?;
        let entry_path = entry.path().into_diagnostic()?.into_owned();
        let mut path = destination.clone();
        path.extend(components(&entry_path)?);
        if path.is_empty() {
            continue;
        }
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            open_dir_path(&root, &path, true)?;
            directory_modes.push((
                path,
                entry.header().mode().unwrap_or(0o755) & SAFE_MODE_MASK,
            ));
            continue;
        }
        let (parent_path, leaf) = split_parent(&path)?;
        let parent = open_dir_path(&root, parent_path, true)?;
        if entry_type.is_file() {
            remove_non_directory(&parent, leaf)?;
            let mode = entry.header().mode().unwrap_or(0o644) & SAFE_MODE_MASK;
            let fd = openat(
                &parent,
                leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_bits_truncate(mode),
            )
            .into_diagnostic()
            .wrap_err_with(|| format!("create archive entry {}", entry_path.display()))?;
            let mut file = File::from(fd);
            std::io::copy(&mut entry, &mut file)
                .into_diagnostic()
                .wrap_err_with(|| format!("write archive entry {}", entry_path.display()))?;
            fchmod(&file, Mode::from_bits_truncate(mode))
                .into_diagnostic()
                .wrap_err_with(|| format!("set archive entry mode {}", entry_path.display()))?;
        } else if entry_type.is_symlink() {
            let target = entry
                .link_name()
                .into_diagnostic()?
                .ok_or_else(|| miette::miette!("symlink entry has no target"))?;
            safe_symlink_target(&target)?;
            remove_non_directory(&parent, leaf)?;
            symlinkat(target.as_os_str(), &parent, leaf)
                .into_diagnostic()
                .wrap_err_with(|| format!("create symlink {}", entry_path.display()))?;
        } else {
            return Err(miette::miette!(
                "unsupported tar entry type for {}",
                entry_path.display()
            ));
        }
    }
    for (path, mode) in directory_modes.into_iter().rev() {
        let directory = open_dir_path(&root, &path, false)?;
        fchmod(&directory, Mode::from_bits_truncate(mode)).into_diagnostic()?;
    }
    Ok(())
}

fn archive<W: Write>(writer: W, workload_root: &Path, source: &Path) -> Result<()> {
    let root = root_fd(workload_root)?;
    let source = target_components(workload_root, source)?;
    let mut archive = tar::Builder::new(writer);
    if source.is_empty() {
        append_directory_contents(&mut archive, &root, Path::new(""))?;
    } else {
        let (parent_path, leaf) = split_parent(&source)?;
        let parent = open_dir_path(&root, parent_path, false)?;
        append_entry(&mut archive, &parent, leaf, Path::new(leaf))?;
    }
    archive
        .finish()
        .into_diagnostic()
        .wrap_err("finish tar archive")
}

fn header(stat: &rustix::fs::Stat, entry_type: tar::EntryType) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_mode(stat.st_mode & SAFE_MODE_MASK);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(stat.st_mtime.try_into().unwrap_or(0));
    header
}

fn append_entry<W: Write>(
    archive: &mut tar::Builder<W>,
    parent: impl AsFd,
    name: &OsStr,
    archive_path: &Path,
) -> Result<()> {
    let stat = statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .into_diagnostic()
        .wrap_err_with(|| format!("inspect {}", archive_path.display()))?;
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFREG {
        let fd = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .into_diagnostic()?;
        let mut header = header(&stat, tar::EntryType::Regular);
        header.set_size(stat.st_size.try_into().into_diagnostic()?);
        header.set_cksum();
        archive
            .append_data(&mut header, archive_path, File::from(fd))
            .into_diagnostic()?;
    } else if kind == libc::S_IFDIR {
        let fd = openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .into_diagnostic()?;
        let mut header = header(&stat, tar::EntryType::Directory);
        header.set_size(0);
        header.set_cksum();
        archive
            .append_data(&mut header, archive_path, std::io::empty())
            .into_diagnostic()?;
        append_directory_contents(archive, &fd, archive_path)?;
    } else if kind == libc::S_IFLNK {
        let target = readlinkat(&parent, name, Vec::new()).into_diagnostic()?;
        let target = PathBuf::from(OsString::from_vec(target.into_bytes()));
        safe_symlink_target(&target)?;
        let mut header = header(&stat, tar::EntryType::Symlink);
        header.set_size(0);
        header.set_cksum();
        archive
            .append_link(&mut header, archive_path, target)
            .into_diagnostic()?;
    } else {
        return Err(miette::miette!(
            "unsupported file type at {}",
            archive_path.display()
        ));
    }
    Ok(())
}

fn append_directory_contents<W: Write>(
    archive: &mut tar::Builder<W>,
    directory: impl AsFd,
    archive_path: &Path,
) -> Result<()> {
    let mut names = Dir::read_from(&directory)
        .into_diagnostic()?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_bytes().to_vec())
        .filter(|name| name != b"." && name != b"..")
        .collect::<Vec<_>>();
    names.sort();
    for name in names {
        let name = OsString::from_vec(name);
        append_entry(archive, &directory, &name, &archive_path.join(&name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_and_absolute_paths() {
        assert!(components(Path::new("../escape")).is_err());
        assert!(components(Path::new("/escape")).is_err());
        assert_eq!(components(Path::new("a/./b")).unwrap().len(), 2);
    }

    #[test]
    fn extraction_never_follows_an_archive_created_symlink() {
        let destination = tempfile::Builder::new()
            .prefix("openshell-transfer-dest-")
            .tempdir_in(".")
            .unwrap();
        let outside = tempfile::Builder::new()
            .prefix("openshell-transfer-outside-")
            .tempdir_in(".")
            .unwrap();
        let destination_name = destination.path().file_name().unwrap().to_owned();
        let outside_path = std::fs::canonicalize(outside.path()).unwrap();
        drop(destination);

        let mut bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut bytes);
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_size(0);
            link.set_cksum();
            builder
                .append_link(&mut link, "link", &outside_path)
                .unwrap();
            let payload = b"escaped";
            let mut file = tar::Header::new_gnu();
            file.set_entry_type(tar::EntryType::Regular);
            file.set_size(payload.len() as u64);
            file.set_mode(0o644);
            file.set_cksum();
            builder
                .append_data(&mut file, "link/pwn", &payload[..])
                .unwrap();
            builder.finish().unwrap();
        }

        assert!(
            extract(
                bytes.as_slice(),
                Path::new("."),
                Path::new(&destination_name)
            )
            .is_err()
        );
        assert!(!outside_path.join("pwn").exists());
        std::fs::remove_dir_all(destination_name).unwrap();
    }
}
