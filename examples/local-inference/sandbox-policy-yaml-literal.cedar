// Literal Cedar encoding of sandbox-policy.yaml (original YAML).
// No identity guard (no process: section in YAML).
// PyPI: no access: field → all HTTP methods permitted.
// NVIDIA: access: full → all HTTP methods permitted.
// include_workdir: true → workdir ReadFile permit.

// Filesystem: read-only paths
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"ReadFile",
    resource  is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/usr"
    || resource in Sandbox::FilesystemPath::"/lib"
    || resource in Sandbox::FilesystemPath::"/etc"
    || resource in Sandbox::FilesystemPath::"/app"
    || resource in Sandbox::FilesystemPath::"/var/log"
    || resource in Sandbox::FilesystemPath::"/proc/self"
    || resource == Sandbox::FilesystemPath::"/dev/urandom"
};

// Filesystem: read-write paths
permit (
    principal is Sandbox::Process,
    action    in [Sandbox::Action::"ReadFile", Sandbox::Action::"WriteFile"],
    resource  is Sandbox::FilesystemPath
)
when {
    resource in Sandbox::FilesystemPath::"/sandbox"
    || resource in Sandbox::FilesystemPath::"/tmp"
    || resource == Sandbox::FilesystemPath::"/dev/null"
};

// include_workdir: true
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"ReadFile",
    resource  is Sandbox::FilesystemPath
)
when {
    principal has workdir
    && resource in principal.workdir
};

// PyPI — no access: field → all methods
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
};

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"files.pythonhosted.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
};

// NVIDIA — access: full → all methods
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"integrate.api.nvidia.com:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
};
