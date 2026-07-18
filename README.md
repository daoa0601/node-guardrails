# Node Guardrails

`@agentic-orch/node-guardrails` contains small, domain-independent Node.js security primitives used by the
Agent Blocks, Drone, Templar, and Nexus projects. It has no runtime dependencies and does not prescribe an
application error model, schema library, or Effect runtime.

> Status: private local workspace module; npm publication is intentionally disabled.

## Public subpaths

- `@agentic-orch/node-guardrails/process` runs an executable directly with an argument array, bounded
  stdout/stderr, a watchdog, graceful-then-forced termination, and optional `AbortSignal`
  cancellation. It never invokes a shell, and a signal that is already aborted prevents spawning.
  On POSIX, termination targets an isolated process group so descendant processes and inherited
  pipes are placed under the same bounded cleanup. On Windows, cleanup is limited to the direct
  child and local pipes; descendant termination cannot be guaranteed without a platform job-object
  integration.
- `@agentic-orch/node-guardrails/http` reads bounded unencoded request bodies, strictly parses JSON media
  types and payloads, compares a configured bearer credential, and writes no-store JSON responses
  with content-length and `nosniff` headers. Request framing accepts no transfer coding or exactly
  plain `chunked`; stacked and unsupported transfer codings are rejected. Every bounded read must
  choose an explicit rejection policy: immediately destroy the request, or send a response with
  keep-alive disabled while draining for a bounded interval before destroying an incomplete body.
- `@agentic-orch/node-guardrails/cas` atomically stages SHA-256-addressed files without overwriting an
  existing digest and verifies file type, ownership, permissions, bounded size, and digest. It
  snapshots caller-owned bytes before awaiting, pins a canonical private root identity, and
  revalidates that identity around pathname operations. `read()` is the only retrieval API and
  returns the exact bytes verified through one open file handle; no verified-path API is exposed.
  The store root and its ancestors must remain a private namespace controlled by the trusted
  effective user. Portable Node.js exposes no descriptor-relative
  `openat`/`linkat` API, so the same effective UID, root/admin access, ACL or mount manipulation,
  filesystems with weak inode semantics, and a precisely timed ancestor swap-and-restore remain
  trusted boundaries; use a native descriptor-relative backend for a hostile namespace.

The package root re-exports all three modules. Applications should prefer subpath imports so their
dependency boundary stays explicit.

## Boundary of responsibility

These primitives report typed neutral failures. Consumers remain responsible for authentication
policy, public error projection, request and metadata schemas, media-specific validation, and
authorization. In particular, the content-addressed store proves byte identity; it does not decide
whether those bytes form a valid PCAP, exercise snapshot, or Drone artifact record.

## Development

Use Node.js and pnpm versions allowed by `package.json`, then run:

```bash
pnpm install --frozen-lockfile
pnpm check
```

The pack check compiles declarations, verifies the root and all subpath exports, installs a
temporary tarball, and smoke-tests its runtime and TypeScript entry points. The tarball is only a
clean-room boundary test for local consumers.
