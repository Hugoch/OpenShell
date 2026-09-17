# Cedar Policy Equivalence Results

**Date:** 2026-09-07  
**Schema:** `schema.cedarschema`  
**Tool:** `cedar symcc equivalent` backed by cvc5 1.3.1

---

## Files

| Label | File | Description |
|---|---|---|
| Original YAML | `sandbox-policy.yaml` | Hand-authored YAML; no `process:` section |
| Synthesized YAML | `sandbox-policy-from-cedar.yaml` | Round-tripped from Cedar; adds `process: sandbox:sandbox`, PyPI `access: read-only` |
| Cedar policy | `policies.cedar` | Final Cedar; adds identity guard, GET-only PyPI, GET/POST NVIDIA, no workdir |

Cedar encodings used as symcc input:

| Cedar file | Encodes |
|---|---|
| `sandbox-policy-yaml-literal.cedar` | `sandbox-policy.yaml` |
| `sandbox-policy-from-cedar-literal.cedar` | `sandbox-policy-from-cedar.yaml` |

---

## Comparison 1 — `sandbox-policy.yaml` vs `policies.cedar`

| Action | Equivalent? | Counterexample |
|---|---|---|
| `ReadFile` | **NO** | `Process{user="sandbox", group=""}` reads `/dev/null` — original allows (no guard), Cedar denies (guard requires both user+group == sandbox) |
| `WriteFile` | **NO** | `Process{user="", group=""}` writes `/dev/null` — original allows (no guard), Cedar denies (guard) |
| `NetworkConnect` | **NO** | `Process{user="", group=""}` → `integrate.api.nvidia.com:443` with `method=""` — original allows (no guard, no method restriction), Cedar denies (guard; additionally `method=""` fails GET\|POST check) |

**Containment:** `policies.cedar ⊂ sandbox-policy.yaml` — Cedar is strictly more restrictive.

---

## Comparison 2 — `sandbox-policy.yaml` vs `sandbox-policy-from-cedar.yaml`

| Action | Equivalent? | Counterexample |
|---|---|---|
| `ReadFile` | **NO** | `Process{user="", group=""}` reads `/dev/null` — original allows (no guard), synthesized YAML denies (identity guard) |
| `WriteFile` | **NO** | `Process{user="", group=""}` writes `/dev/null` — original allows (no guard), synthesized YAML denies (identity guard) |
| `NetworkConnect` | **NO** | `Process{user="", group=""}` → `integrate.api.nvidia.com:443` with `method=""` — original allows (no guard), synthesized YAML denies (identity guard) |

**Containment:** `sandbox-policy-from-cedar ⊂ sandbox-policy.yaml` — synthesized YAML is strictly more restrictive.

---

## Root causes of divergence

| Difference | `sandbox-policy.yaml` | Derived policies |
|---|---|---|
| Identity guard | None (no `process:` section) | `forbid unless user==sandbox && group==sandbox` |
| PyPI HTTP method | Unrestricted (no `access:` field) | GET-only (`access: read-only`) |
| NVIDIA HTTP method | Unrestricted (`access: full`) | GET or POST (`policies.cedar`) / unrestricted (`sandbox-policy-from-cedar.yaml`) |
| Workdir | `include_workdir: true` | Present in `sandbox-policy-from-cedar.yaml`; absent in `policies.cedar` |

The identity guard is the dominant cause: it appears as the first counterexample in all six checks because it eliminates the entire space of non-sandbox principals that the original YAML permits.

---

## Interpretation

Both derived policies are safe: `derived ⊂ original` means the Cedar translation and round-tripped YAML never grant access the original YAML did not intend. The hardening is deliberate — the original YAML's missing `process:` section is a latent privilege-escalation risk that the translation corrected.
