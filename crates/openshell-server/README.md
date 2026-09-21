<!-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# OpenShell server

`openshell-server` implements the gateway control plane. The stable gateway
boundaries and data flows are documented in
[`architecture/gateway.md`](../../architecture/gateway.md).

## Configuration delivery scheduler

Configuration publishers enqueue sandbox/component keys rather than payloads.
The scheduler retains at most 1,024 running or queued keys. Repeated requests
for one key coalesce, and a mutation that arrives during delivery returns that
key to the FIFO tail for another pass.

Delivery admission allows at least 64 workers. Snapshot build concurrency is
also limited by the database pool, so a scoped burst cannot create the same
number of concurrent database and credential-backend reads. Fanout waits for
pending capacity. If direct publication overflows, the scheduler requests one
coalesced all-connected repair pass. Two reserved fanout scopes keep that repair
path available when workspace fanout is full.

The router owns session lookup, encoded-size checks, sequence allocation, and
enqueue. Delivery workers build current state only after they obtain capacity.
The owner reconciler remains the fallback for build, routing, or session
failures.
