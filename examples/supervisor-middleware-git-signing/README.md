<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Git commit signing supervisor middleware prototype

This example tests whether an operator-run OpenShell supervisor middleware can sign commits without mounting a signing key into the sandbox. It uses the streaming `HttpRequestPreCredentials.Evaluate` API to intercept Git smart-HTTP `git-receive-pack` requests after network policy admission and before provider credential injection. The service selects `OWNED_STREAM_BYTES`, accepts bounded 64 KiB units into an unlinked temporary file, rewrites the pushed commit objects with SSH signatures, and streams the replacement request back in bounded units.

The sandbox sees neither the private key nor the signature operation. Its Git client creates ordinary unsigned commits and pushes over HTTPS.

## What the prototype does

For each direct branch update in a push, the service:

1. Derives a bounded `github.com/<org>/<repo>.git` upstream URL from the policy-admitted request target.
2. Shallow-fetches the upstream default branch and updated branch tips into a temporary bare repository. This supplies bases omitted from normal thin pushes.
3. Decodes the receive-pack command pkt-lines and packfile, then walks only commits that are not already reachable from the fetched upstream refs.
4. Removes any existing commit signature and signs the exact rewritten commit payload with `ssh-keygen -Y sign -n git`.
5. Rewrites parent object IDs, creates a replacement thin pack, and substitutes the new branch-tip object ID in the receive-pack command.
6. Returns the modified body to the supervisor, which forwards it with the sandbox's normal GitHub credential.

The signing key is a service startup argument, not policy-controlled middleware configuration. A sandbox cannot select an arbitrary host file to sign with.

## Build and test

The test constructs a two-commit push larger than the former 4 MiB unary limit, transforms it, sends the replacement request through Git's real `receive-pack --stateless-rpc`, checks the updated branch tip, and verifies both SSH signatures with `git verify-commit`.

```shell
cargo test --manifest-path examples/supervisor-middleware-git-signing/Cargo.toml
```

The example requires `git` and `ssh-keygen` on the host.

## Run the service

Use an SSH key that is also registered as a signing key with the Git forge. GitHub distinguishes signing keys from authentication keys even when the same public key material is used.

The service requires TLS and verifies every OpenShell caller with an exact-audience extension JWT. Provision a service certificate and private key whose DNS name matches the middleware endpoint, the issuing CA certificate for the gateway registration, and the Ed25519 public key configured in `[openshell.gateway.gateway_jwt]`.

```shell
cargo run \
  --manifest-path examples/supervisor-middleware-git-signing/Cargo.toml \
  -- \
  --bind 0.0.0.0:50051 \
  --signing-key /run/secrets/git-signing-key \
  --tls-cert /run/secrets/git-signer.pem \
  --tls-key /run/secrets/git-signer-key.pem \
  --extension-public-key /run/secrets/openshell-extension-public.pem \
  --expected-gateway-id openshell \
  --audience urn:openshell:extension:middleware:local-git-signer \
  --max-concurrent-signings 2 \
  --signing-timeout-seconds 25
```

Register the local service in `gateway.toml`. A container-backed gateway can reach a host service through `host.openshell.internal`; a host-native gateway can use `127.0.0.1`.

```toml
[[openshell.supervisor.middleware]]
name = "local-git-signer"
grpc_endpoint = "https://host.openshell.internal:50051"
tls_ca_cert_path = "/etc/openshell/certs/git-signer-ca.pem"
audience = "urn:openshell:extension:middleware:local-git-signer"
max_payload_bytes = 65536
timeout = "30s"

[openshell.gateway.gateway_jwt]
signing_key_path = "/etc/openshell/jwt/signing.pem"
public_key_path = "/etc/openshell/jwt/public.pem"
kid_path = "/etc/openshell/jwt/kid"
gateway_id = "openshell"
ttl_secs = 3600
```

The `public_key_path` file must be the same key supplied to the service with `--extension-public-key`. The registration audience must exactly match `--audience`, and `gateway_id` must exactly match `--expected-gateway-id`. The service authorizes gateway callers for discovery and configuration validation and sandbox supervisor callers for request evaluation.

Set `max_payload_bytes` to 65536 as shown for full-size stream units. A lower positive value uses smaller output units; the value does not cap the complete push. OpenShell separately enforces a bounded deferred-storage limit for owned streams. Keep the registration timeout above the service's signing timeout so OpenShell can receive either the signed output or a controlled failure.

Restart the gateway after adding the static registration, then replace `<org>` and `<repo>` in [policy.yaml](policy.yaml) and create a sandbox with that policy. Keep the endpoint on `fail_closed`: reject a push rather than forwarding it unsigned when signing fails.

The service skips unrelated GitHub HTTP requests during preflight. It inspects only `POST` requests whose path ends in `/git-receive-pack` and whose content type is `application/x-git-receive-pack-request`. This example accepts only validated HTTPS targets on `github.com:443` with a two-segment repository path.

The signer implements `SupervisorMiddleware` for discovery and configuration validation, and serves `HttpRequestPreCredentials` alongside it. The request stream is the only HTTP request middleware API.

## Resource bounds and cancellation

Input and replacement packs stay in unlinked temporary files. The service parses only a bounded 1 MiB receive-pack prefix in memory, feeds the input pack directly to `git index-pack`, and writes the replacement pack directly to its output file. It emits the replacement to OpenShell in bounded units.

`--max-concurrent-signings` limits active Git rewrite workers. `--signing-timeout-seconds` covers upstream fetches, graph rewriting, signing, and pack generation. If the OpenShell request is canceled or the deadline expires, the service kills the active `git` or `ssh-keygen` subprocess and waits for it to exit. Subprocess diagnostic capture is bounded and is not returned to the sandbox.

## Prototype limits

- Owned streams are available only with `on_error: fail_closed`. Once the service acknowledges ownership, OpenShell has no replay copy and cannot safely fail open.
- The implementation supports SHA-1 repositories and direct `refs/heads/*` updates. It rejects SHA-256 repositories, annotated-tag pushes, push certificates, and other ref types.
- Each push shallow-fetches upstream objects before signing. The host must be able to reach the repository, and private repositories need a non-interactive Git credential helper available to the local middleware user. A production deployment should use a bounded object cache and explicit credential plumbing.
- The service shells out to the host's `git` and `ssh-keygen`. Run it with OS-level CPU, memory, process, temporary-storage, and network limits in addition to its own concurrency and time bounds.
- Rewriting commit object IDs means the sandbox's local branch still points to the unsigned commit after a successful push. A subsequent fetch updates the remote-tracking ref, but the local branch must be reconciled with the rewritten history. This is the largest workflow issue for transparent push-time signing.
- The example has protocol and local end-to-end Git coverage, not a live GitHub push. Test against a disposable repository before using a real signing key.

These constraints make the approach viable as a focused deployment or proof of concept, but not yet transparent enough for general production pushes. A first-class commit-signing operation invoked before Git creates the final local object would avoid the local/remote object-ID split while still keeping the private key outside the sandbox.
