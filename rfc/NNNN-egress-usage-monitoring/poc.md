# Run a Sandbox with an Egress Budget

This runbook starts a local gateway, creates one sandbox with a request
budget, and shows the budget deny and the usage report. It uses the branch
`poc/egress-usage-monitoring`.

## Requirements

- Linux with Docker. Ubuntu 24.04 works. Docker Desktop on macOS does not work,
  because the supervisor dials the gateway at `127.0.0.1`.
- `mise`. Run `mise install` in the repository.

## 1. Build and start the gateway

```shell
mise x -- cargo build -p openshell-cli --bin openshell
export PATH="$PWD/target/debug:$PATH"
CONTAINER_ENGINE=docker bash tasks/scripts/e2e-build-workload.sh
OPENSHELL_SANDBOX_IMAGE=openshell/e2e-python:dev \
  OPENSHELL_SANDBOX_IMAGE_PULL_POLICY=never \
  mise run gateway:docker
```

The gateway task builds the supervisor image if it is missing. Keep the gateway
running, and use a second terminal for the next steps:

```shell
export PATH="$PWD/target/debug:$PATH"
openshell gateway use docker-dev
```

## 2. Start a local upstream

```shell
python3 -m http.server 8000 --bind 0.0.0.0
```

## 3. Write the policy

Save this file as `budget-policy.yaml`. The budget allows 5 requests per minute
to the upstream and denies the rest with HTTP 429.

```yaml
version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  local_api:
    name: local_api
    endpoints:
      - host: host.openshell.internal
        port: 8000
        protocol: rest
        enforcement: enforce
        access: read-only
        allowed_ips: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    binaries:
      - path: "/**"

network_budgets:
  local-requests:
    policies: [local_api]
    requests_per_minute: 5
    on_exceed: deny
```

## 4. Create the sandbox and send traffic

```shell
openshell sandbox create --detach --name budget-demo \
  --policy budget-policy.yaml -- sh -c 'sleep infinity'
openshell sandbox exec --name budget-demo --no-tty -- python3 -c '
import urllib.request, urllib.error
for _ in range(10):
    try:
        print(urllib.request.urlopen("http://host.openshell.internal:8000/").status, end=" ")
    except urllib.error.HTTPError as error:
        print(error.code, end=" ")
print()'
```

The output is 5 times `200`, then 5 times `429`.

## 5. Read the usage

The supervisor reports usage every 60 seconds. After one report, run:

```shell
openshell sandbox usage budget-demo
openshell logs budget-demo --source sandbox -n 100 | grep -E 'egress\.|NET:CLOSE'
```

The `DENIED` column shows 5. The findings show `egress.budget_exceeded` for
the budget `local-requests`.

## 6. Clean up

```shell
openshell sandbox delete budget-demo
```

Delete the sandboxes before you stop the gateway. A running sandbox does not
survive a gateway restart.
