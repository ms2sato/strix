# Strix hardening fork — purpose, isolation, and upstream tracking

This repository is a **hardening / evaluation fork** of [Strix](https://github.com/usestrix/strix),
the open-source autonomous AI pentesting tool. It does **not** change what Strix
does. It adds a safety/isolation layer around it so Strix can be run and
evaluated locally under strong containment, plus a few small, default-off,
opt-in options. Upstream is respected; everything here is meant to be additive
and, where it is a genuine fix or improvement, contributable back upstream.

> If you want to *use* Strix, prefer upstream. This fork is for people who need
> to run it in a locked-down lab (air-gapped-style egress control, inspected
> Docker access, pinned supply chain) and to study its behavior safely.

## Why a fork

Autonomous pentest agents drive a browser and a shell against targets, call an
external LLM, and (upstream) can phone home for telemetry, update checks, and a
hosted relay. For a careful local evaluation we want to bound all of that: one
auditable egress path, no outbound from the component that touches the target,
a reproducible supply chain, and no background network of our own. The fork
packages those controls so a run is safe-by-construction rather than by caution.

## Isolation architecture (method, generalized)

The design is independent of any particular target. Its pillars:

- **Single egress chokepoint.** All controller traffic is forced through one
  allowlist forward proxy. The default allowlist is **deny-all**. Only the LLM
  API domain is allowed, and only for the duration of a scan; it is restored to
  deny-all afterward.
- **Egress-less sandbox and target.** The sandbox (which drives the target) and
  the target itself are on internal-only Docker networks that are **not**
  attached to the egress proxy, so they have **zero** outbound path. The
  controller reaches the in-sandbox proxy directly over the lab network.
- **Inspected Docker access (socket proxy).** Instead of handing the controller
  a raw Docker socket, a small create-inspecting proxy allows only: the pinned
  sandbox image, the lab network, non-privileged containers, a minimal
  capability set, and **read-only** bind mounts whose host path sits under an
  explicitly allowlisted prefix. Everything else is denied.
- **Network isolation.** Lab networks are `internal: true` with an isolated
  gateway, i.e. no NAT to the internet.
- **Pinned, from-source builds.** Base images by digest; CLI tools by version +
  sha256; Python by a hashed, universal lockfile — instead of `latest` tags or
  `curl | sh`. A pin-check script keeps these honest.
- **No background network of our own.** Telemetry and update checks are off; the
  hosted-relay / cloud URL (`STRIX_APP_URL`) is pointed at a dead local port so
  any report/relay egress fails closed; the local results viewer only reads
  run files from disk.
- **Per-container sandbox CA.** The TLS-intercept CA is generated at container
  start (not baked into the image), so every container has its own key.

## Running it safely

Exact commands and environment live in [`lab/README.md`](../lab/README.md) and
the `*.example` files next to each config. In outline:

1. Copy `lab/.env.example` → `lab/.env` and set your `LAB_UID` / `LAB_GID` /
   `DOCKER_GID`.
2. Put the LLM API key in a `chmod 600` file outside the repo. Never commit a
   key, and never paste one into logs or chat.
3. Build the pinned images and bring up the egress proxy with the **deny-all**
   allowlist; run the isolation check; then allow only the LLM domain for the
   scan and restore deny-all when it finishes.
4. The optional local results viewer is exposed only through an IP-restricted
   front proxy. The real bind address and allowed client CIDR live in a
   **local, gitignored** config generated from the committed `*.example`
   template — real addresses are never committed to this public repo.

Real IPs, keys, and credentials never belong in this repository. Config that
must contain them is gitignored and ships only as a placeholder `.example`.

## Opt-in options (default off = upstream behavior)

These are gated so an unset/plain configuration behaves exactly like upstream.
They only engage on explicit opt-in and are intended to be safe to upstream.

- **`STRIX_LAB_PROFILE=claude`** — turns on optimizations that are only
  meaningful with Anthropic prompt caching. Unset = upstream behavior (it will
  auto-detect an Anthropic model only as a convenience, and even then each
  optimization still needs its own flag below).
- **`STRIX_SPECIALIST_LLM`** — run spawned specialist/child agents on a cheaper
  Claude model while the root agent stays on `STRIX_LLM`. Applied only under the
  Claude profile and only when the value names a Claude model; otherwise ignored
  (children use `STRIX_LLM`, i.e. upstream).
- **`STRIX_TOOL_OUTPUT_PARSE`** (+ `STRIX_TOOL_OUTPUT_PARSE_LEVEL`) — a
  conservative, fail-open condenser for known-verbose tool output (e.g. large
  JSON scanner output or large HTTP responses) before it enters agent history.
  The full raw output is always written to disk and pointed at first, findings
  are never dropped, and unrecognized output is passed through unchanged.
  Default off = upstream raw behavior.

Upstream context-management knobs (`STRIX_CONTEXT_*`, `STRIX_TOOL_OUTPUT_MAX_*`)
are unchanged here and are simply tuned per run / per provider.

## Upstream tracking (A / B / C)

- **A — safety & isolation layer: owned here, kept fixed.** The egress
  chokepoint, the socket proxy, network isolation, pinned from-source builds,
  and telemetry/relay-off. These are the point of the fork and are not delegated
  upstream.
- **B — bug fixes** and **C — optimizations: prefer upstream.** Keep such
  changes minimal and default-off/opt-in, and aim to contribute them upstream
  rather than carry divergence. Track a known-good upstream tag and take updates
  **deliberately**, not automatically.
- **Every uptake is gated.** Before adopting an upstream change, it must pass the
  isolation check, the spec/test suite, and a smoke scan. If any gate fails, the
  update is not adopted until it does.

## Relationship to upstream

This fork is a constructive hardening and evaluation effort. It stands on
upstream Strix, keeps its own additions small and opt-in, and tries to give back
the parts that are generally useful. Please support and cite upstream.
