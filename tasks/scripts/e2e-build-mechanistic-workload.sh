#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=tasks/scripts/container-engine.sh
source "${ROOT}/tasks/scripts/container-engine.sh"
ce_build --load --file "${ROOT}/e2e/policy-advisor/Dockerfile.workload" \
  --tag openshell/e2e-mechanistic:dev \
  "${ROOT}/e2e/policy-advisor"
