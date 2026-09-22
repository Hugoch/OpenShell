# Sandbox Policy Quickstart

This example demonstrates a deny-allow-deny network policy workflow against a
local Docker gateway. It builds a versioned Ubuntu 24.04 image with `curl` and
CA certificates, keeps the sandbox main process running, and checks both the
allowed and denied outcomes.

## Prerequisites

- A current OpenShell CLI connected to a matching local gateway with the Docker
  compute driver.
- Docker.
- `jq`.
- No active gateway-global policy. The script also creates the sandbox with no
  providers and checks that its effective policy starts without network rules.

## Run the Demo

Run the script from the repository root:

```shell
bash examples/sandbox-policy-quickstart/demo.sh
```

Pass a unique sandbox name when `policy-demo` is already in use:

```shell
bash examples/sandbox-policy-quickstart/demo.sh policy-demo-2
```

The script cleans up only the sandbox that it successfully creates. It stops if
the selected sandbox name already exists.

## What the Demo Verifies

The script performs these checks:

1. `/usr/bin/curl` and the CA certificate bundle exist in the image.
2. A request to `https://api.github.com/zen` fails before a network rule exists.
3. Sandbox logs show the connection denial without a WARN-level filter.
4. An incremental update adds an enforced REST rule for `/usr/bin/curl`.
5. A GET request succeeds and a POST request returns `policy_denied`.
6. A structured base-policy export excludes display and provider metadata,
   retains startup fields, and round-trips through full replacement.
7. Removing the named rule restores default-deny behavior.

[`policy.yaml`](policy.yaml) is a complete create-time file showing the same
network rule. The demo uses `openshell policy update` instead so it does not
replace the sandbox's startup-time filesystem or process settings.

For the guided version, refer to
[Write Your First Sandbox Network Policy](https://docs.nvidia.com/openshell/latest/get-started/tutorials/first-network-policy).
