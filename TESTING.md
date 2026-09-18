# Testing

This document defines the desired testing model for OpenShell. It is a target
state for migrating host-managed and `mise`-managed tests to reproducible Nix
environments and `tmachine` wherever practical. It distinguishes the behavior
required for a green change, release validation, specialized testing, and the
current migration gaps.

Use [CI.md](CI.md) for current workflow mechanics. `flake.nix`,
`tests/config.nix`, and `tests/suites` define the emerging test interface;
`mise tasks` remains the inventory for paths that have not yet migrated.

## Execution model

OpenShell uses two primary test environments:

- Source-level checks run directly in Nix-provided environments. Nix pins the
  compiler, tools, and native dependencies while preserving a short edit and
  unit-test loop.
- Integration and Linux installation tests run through `tmachine`. Nix builds
  the candidate artifacts and test archives; `tmachine` creates a disposable
  guest, applies scenario setup and installation playbooks, and runs a selected
  testsuite.

`flake.lock` pins the build and test inputs. `tests/artifacts.nix` defines the
candidate artifacts, `tests/config.nix` defines machines and scenarios,
`tests/ansible` owns guest setup and installation, and `tests/suites` owns test
behavior.

A direct host or external workflow remains appropriate when `tmachine` cannot
represent the required environment, such as native Windows or macOS behavior,
GPU hardware, or an unsupported orchestration or virtualization topology. Such
paths are exceptions rather than a second preferred test framework.

`mise` tasks may remain as migration bridges, but new integration behavior
should not depend exclusively on a `mise` task or add another host-managed
harness when a Nix and `tmachine` path is possible.

## Test dimensions

Keep these dimensions separate so CI can select useful combinations without
creating an indiscriminate cross-product:

| Dimension | Meaning | Examples |
|---|---|---|
| Platform | Host architecture and operating system used for source checks or to run `tmachine` | Linux x86_64, Linux ARM64, macOS ARM64 |
| Environment | Guest operating system and execution mechanism under test | Fedora with Podman, Ubuntu with Docker, Kubernetes, VM driver |
| Configuration | A product wiring choice independent of the environment | In-process driver, external driver, provider configuration |
| Installation | How candidate artifacts enter the environment | Direct binaries and images, RPM, DEB, Helm, Snap |
| Testsuite | The reusable assertions applied after installation | Conformance, a feature suite, or a driver suite |

For example, an external driver is a configuration axis rather than a new
environment. The VM driver is an environment or product configuration, not an
installation mechanism.

CI explicitly lists scenario and testsuite pairs so GitHub Actions can execute
them in parallel. Those entries must reference scenarios declared in
`tests/config.nix`; workflows must not duplicate the guest setup or installation
logic.

## Source-level validation

Every change must run this minimum source gate:

- Rust formatting and linting;
- Rust unit tests;
- compile-time and other static analysis needed to catch feature and platform
  conditional-compilation failures;
- dependency-policy checks; and
- repository-level security checks using their existing configurations and
  enforcement behavior.

Rust validation runs on multiple platforms for every change because conditional
compilation is a material source of regressions. The initial required set is:

- Linux x86_64;
- Linux ARM64; and
- macOS ARM64.

Windows x64 and ARM64 compilation is desirable, but whether it joins the
required source gate remains deferred until the other target matrices are
established.

SDK checks are conditional:

- a change local to one SDK runs that SDK's formatting, linting, generated-file
  checks, build, and unit tests; and
- a shared protobuf change runs every affected SDK's checks.

Packaging validation is also conditional. RPM, DEB, Helm, Snap, Homebrew, and
other packaging checks run when their inputs change. Selection must account for
transitive inputs such as shared binaries, schemas, versioning, installers, and
release metadata. If CI cannot safely determine the affected set, it runs the
broader set.

The desired implementation exposes these checks through Nix environments or
flake outputs. Current `mise` tasks remain valid until equivalent Nix entry
points exist.

## Integration test classes

Initial integration coverage has three classes.

### Conformance

Conformance tests cover driver-agnostic behavior that must work regardless of
environment and OpenShell configuration. Existing driver-agnostic E2E behavior
should migrate into this suite rather than remain copied across driver harnesses.

The initial conformance suite is CLI-focused. API- and SDK-level conformance is
outside the initial scope.

### Feature-specific

Feature-specific tests require external functionality or an additional product
configuration. Suites live under `tests/suites/features/<feature>` and are
independently selectable in CI. Examples include provider-refresh and
Keycloak-backed authentication.

The testsuite owns the lifecycle of its external dependencies. A feature suite
should provision, configure, diagnose, and remove services such as Keycloak
instead of turning each dependency into a permanent base environment.

### Driver-specific

Driver-specific tests exercise behavior unique to a compute driver. Suites live
under `tests/suites/drivers/<driver>`. The initial model uses one coarse suite
per driver; finer capability-level selection is not required.

Common behavior belongs in conformance. A driver suite must not retain a
driver-local copy of an assertion that is valid for every driver.

## Merge integration matrix

A green merge runs a fixed integration matrix. Change-aware scenario selection
may be added later as an optimization, but it is not part of the initial design.

Conformance runs against these five environment classes:

1. Fedora with rootful Podman.
2. Fedora with rootless Podman.
3. Ubuntu with Docker.
4. A Kubernetes distribution.
5. The VM driver.

The exact Kubernetes distribution is deferred. k3s running inside a guest is a
candidate, but the matrix should not encode that choice until it has been
validated.

The five environments are the initial default rather than a permanent minimum.
Maintainers may add or remove entries when the execution cost and defect-finding
value justify the change.

Each feature-specific suite runs against at least one representative compatible
environment. Each driver-specific suite runs against at least one representative
environment for that driver. A feature or driver suite need not run across the
entire conformance matrix.

External-driver mode exists to test the gateway-to-driver interaction; external
drivers are not currently release artifacts. One representative external-driver
scenario is sufficient. Its environment is deferred.

Merge integration initially installs directly built binaries and images. Package
installation may be added to merge testing later, but it is not required for the
initial gate.

## Specialized tests

GPU and Windows tests remain label-selected, opt-in CI suites. They do not form
part of the initial default integration matrix.

Performance, scalability, soak, and generalized failure-recovery testing are
outside the current testing plan. The document should not imply gates or service
levels for those classes.

## Release validation

Release validation tests candidate artifacts before publication. It initially
uses the same representative environment model rather than constructing the
full cross-product of operating systems, architectures, drivers,
configurations, installation mechanisms, and testsuites.

`tmachine` installs and validates these candidate installation mechanisms:

| Installation mechanism | Representative environment | Initial validation |
|---|---|---|
| RPM | Fedora | Install, start OpenShell, and run conformance |
| DEB | Ubuntu | Install, start OpenShell, and run conformance |
| Snap | Ubuntu | Install, start OpenShell, and run conformance |
| Helm | Kubernetes | Install, start OpenShell, and run conformance |
| Homebrew | Native macOS path | Reuse the existing path where available; deeper candidate validation is a follow-up |

Conformance is sufficient as the initial post-install suite. Release validation
runs for every candidate release; change-aware optimization is not initially
required. Expanding the environment or installation matrix is opt-in and should
target a specific risk rather than form a simple cross-product.

Upgrade and backward-compatibility testing is a likely release follow-up, but it
is not part of the initial release gate.

## Local build and test cycle

The default local integration environment is Ubuntu with Docker, running the
conformance suite. From the repository root:

```shell
nix run .#build-artifacts
nix run .#tmachine -- test ubuntu-docker-rootful conformance
```

`build-artifacts` produces the binaries, images, Helm chart, and conformance
archive expected by the current tmachine scenarios. Nix and tmachine caches may
reuse immutable setup and installation layers, while each test runs on a fresh
writable overlay.

Developers select another scenario or testsuite explicitly when working on a
driver or feature. CI runs the complete fixed matrix in parallel; contributors
do not need to reproduce every CI pair locally before review.

## Test behavior and diagnostics

Tests must be deterministic, bounded, isolated from unrelated developer or CI
state, and safe to run concurrently. They use exact-revision candidate artifacts
and immutable base inputs. Setup and cleanup belong to the scenario or
testsuite, not to workflow-specific shell steps.

Each environment and testsuite defines the logs needed to diagnose its failures.
The current conformance suite prints command diagnostics and gateway journal
logs on failure. A common structured reporting contract, standardized artifact
retention, and guest snapshot behavior are deferred.

Bug fixes should include regression coverage at the lowest effective layer. A
test may move to tmachine and be removed from its legacy path in the same change
when the new suite provides equivalent behavior coverage; parallel execution is
not required solely for migration.

## Migration plan

Migrate coherent behavior rather than wrapping every existing command unchanged:

1. Expose the required candidate artifacts or test archives through
   `tests/artifacts.nix`.
2. Move driver-agnostic behavior into `tests/suites/conformance`.
3. Move external-dependency behavior into `tests/suites/features/<feature>`.
4. Move driver-specific behavior into `tests/suites/drivers/<driver>`.
5. Add scenario setup and installation through `tests/config.nix` and
   `tests/ansible`.
6. Add explicit scenario/testsuite pairs to the CI matrix for parallel
   execution.
7. Remove the legacy E2E path and `mise` entry point once the tmachine path has
   equivalent coverage.
8. Add candidate RPM, DEB, Snap, and Helm installation scenarios to release
   validation and run conformance after installation.

The current foundation includes Nix artifact builders, Ubuntu/Docker and
Fedora/Podman tmachine scenarios, a CLI conformance suite, and a reusable CI
workflow. The remaining legacy Rust, Python, MCP, driver, Kubernetes, GPU, and
installation paths should migrate only where tmachine can faithfully represent
their requirements.

## Deferred decisions

The initial model intentionally leaves these choices open:

- the Kubernetes distribution used by the merge matrix;
- the representative environment for external-driver compatibility;
- when Windows compilation becomes a required source gate;
- a standardized tmachine reporting and artifact-retention contract;
- package-installation scenarios in ordinary merge CI;
- candidate-artifact Homebrew validation beyond the existing native path;
- release upgrade and backward-compatibility suites;
- API- and SDK-level conformance; and
- change-aware integration and release-matrix selection.
