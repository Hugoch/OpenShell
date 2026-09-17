// Literal Cedar encoding of sandbox-policy-from-cedar.yaml.
// process: sandbox:sandbox → identity guard.
// PyPI: access: read-only → GET only.
// NVIDIA: access: full → all methods.
// include_workdir: true → workdir ReadFile permit.

// Identity guard (process: run_as_user: sandbox / run_as_group: sandbox)
forbid (principal is Sandbox::Process, action, resource)
unless {
    principal.user  == Sandbox::User::"sandbox"
    && principal.group == Sandbox::Group::"sandbox"
};

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

// PyPI — access: read-only → GET only
permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"pypi.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
    && context.method == "GET"
};

permit (
    principal is Sandbox::Process,
    action    == Sandbox::Action::"NetworkConnect",
    resource  == Sandbox::NetworkEndpoint::"files.pythonhosted.org:443"
)
when {
    context.binary == Sandbox::FilesystemPath::"/sandbox/.venv/bin/python3"
    && context.method == "GET"
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
