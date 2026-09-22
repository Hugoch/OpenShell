#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Run the deny-allow-deny policy tutorial against a local Docker gateway.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_NAME="${1:-policy-demo}"
IMAGE_NAME="${POLICY_DEMO_IMAGE:-openshell-policy-quickstart:0.1}"
CREATED=false
BASE_POLICY=""

cleanup() {
    if [[ -n "$BASE_POLICY" && -f "$BASE_POLICY" ]]; then
        rm -f -- "$BASE_POLICY"
    fi
    if [[ "$CREATED" == true ]]; then
        openshell sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        printf 'Required command not found: %s\n' "$1" >&2
        exit 1
    fi
}

step() {
    printf '\n==> %s\n' "$1"
}

policy_dns_denial_count() {
    awk '
        /NET:REFUSE/ && /api\.github\.com:53/ && /reason:policy_dns_ineligible/ {
            count++
        }
        END { print count + 0 }
    '
}

require_command docker
require_command jq
require_command openshell

if openshell sandbox get "$SANDBOX_NAME" >/dev/null 2>&1; then
    printf 'Sandbox %s already exists; choose another name.\n' "$SANDBOX_NAME" >&2
    exit 1
fi

step "Build the tool-equipped tutorial image"
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

step "Create a long-running sandbox without providers"
openshell sandbox create \
    --name "$SANDBOX_NAME" \
    --from "$IMAGE_NAME" \
    --no-auto-providers \
    --no-tty \
    --detach \
    -- /usr/bin/sleep infinity
CREATED=true

step "Verify the tutorial starts without an effective network grant"
if openshell policy get "$SANDBOX_NAME" --full --output json \
    | jq -e '.policy.network_policies // {} | length == 0' >/dev/null; then
    printf 'Effective policy has no network rules.\n'
else
    printf 'The effective policy already contains network rules. Use an isolated gateway without a global policy or attached providers.\n' >&2
    exit 1
fi

step "Confirm curl and CA certificates are installed"
openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    test -x /usr/bin/curl
openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    test -r /etc/ssl/certs/ca-certificates.crt

step "Confirm the initial request is denied by OpenShell"
set +e
INITIAL_RESPONSE="$(openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    /usr/bin/curl --silent --show-error --fail --max-time 10 \
    https://api.github.com/zen 2>&1)"
INITIAL_STATUS=$?
set -e
printf '%s\n' "$INITIAL_RESPONSE"
if [[ $INITIAL_STATUS -eq 0 ]]; then
    printf 'Expected the initial request to be denied, but it succeeded.\n' >&2
    exit 1
fi
INITIAL_DENIAL_CONFIRMED=false
for _ in {1..10}; do
    INITIAL_LOGS="$(openshell logs "$SANDBOX_NAME" --since 5m --source sandbox -n 100)"
    if [[ "$(policy_dns_denial_count <<<"$INITIAL_LOGS")" -ge 1 ]]; then
        INITIAL_DENIAL_CONFIRMED=true
        break
    fi
    sleep 1
done
printf '%s\n' "$INITIAL_LOGS"
if [[ "$INITIAL_DENIAL_CONFIRMED" != true ]]; then
    printf 'The failed request was not confirmed as an OpenShell policy denial.\n' >&2
    exit 1
fi

step "Add an enforced read-only REST rule"
openshell policy update "$SANDBOX_NAME" \
    --rule-name github_readonly \
    --binary /usr/bin/curl \
    --add-endpoint api.github.com:443:read-only:rest:enforce \
    --wait

step "Confirm GET succeeds"
openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    /usr/bin/curl --silent --show-error --fail --max-time 15 \
    https://api.github.com/zen

step "Confirm POST is denied by OpenShell"
POST_RESPONSE="$(openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    /usr/bin/curl --silent --show-error --max-time 15 \
    --request POST https://api.github.com/zen || true)"
printf '%s\n' "$POST_RESPONSE"
if [[ "$POST_RESPONSE" != *policy_denied* ]]; then
    printf 'Expected an OpenShell policy_denied response for POST.\n' >&2
    exit 1
fi
openshell logs "$SANDBOX_NAME" --since 5m --source sandbox -n 20

step "Round-trip the editable base policy without display or provider metadata"
BASE_POLICY="$(mktemp /tmp/openshell-policy-demo.XXXXXX.json)"
openshell policy get "$SANDBOX_NAME" --base --output json \
    | jq -e '.policy' >"$BASE_POLICY"
jq -e \
    '.version == 1 and .filesystem_policy != null and .landlock != null' \
    "$BASE_POLICY" >/dev/null
jq -e \
    '[(.network_policies // {}) | keys[] | startswith("_provider_")] | any | not' \
    "$BASE_POLICY" >/dev/null
openshell policy set "$SANDBOX_NAME" --policy "$BASE_POLICY" --wait

step "Remove the rule and confirm default-deny again"
DENY_LOG_COUNT_BEFORE="$(
    openshell logs "$SANDBOX_NAME" --since 5m --source sandbox -n 100 \
        | policy_dns_denial_count
)"
openshell policy update "$SANDBOX_NAME" \
    --remove-rule github_readonly \
    --wait
set +e
FINAL_RESPONSE="$(openshell sandbox exec -n "$SANDBOX_NAME" --no-login-shell -- \
    /usr/bin/curl --silent --show-error --fail --max-time 10 \
    https://api.github.com/zen 2>&1)"
FINAL_STATUS=$?
set -e
printf '%s\n' "$FINAL_RESPONSE"
if [[ $FINAL_STATUS -eq 0 ]]; then
    printf 'Expected the request to be denied after rule removal.\n' >&2
    exit 1
fi
FINAL_DENIAL_CONFIRMED=false
for _ in {1..10}; do
    FINAL_LOGS="$(openshell logs "$SANDBOX_NAME" --since 5m --source sandbox -n 100)"
    DENY_LOG_COUNT_AFTER="$(policy_dns_denial_count <<<"$FINAL_LOGS")"
    if ((DENY_LOG_COUNT_AFTER > DENY_LOG_COUNT_BEFORE)); then
        FINAL_DENIAL_CONFIRMED=true
        break
    fi
    sleep 1
done
printf '%s\n' "$FINAL_LOGS"
if [[ "$FINAL_DENIAL_CONFIRMED" != true ]]; then
    printf 'The final failed request was not confirmed as an OpenShell policy denial.\n' >&2
    exit 1
fi

printf '\nDeny-allow-deny workflow completed for %s.\n' "$SANDBOX_NAME"
