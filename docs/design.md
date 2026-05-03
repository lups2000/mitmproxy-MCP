# mitmproxy MCP Design

This document explains the design of the repository, the architecture choices, and the current direction of the project.

## Product Goal

The project goal is:

> make `mitmproxy` available to agents the way `mitmweb` makes it available to humans

That leads to one important rule:

> `mitmproxy` is the source of truth, and MCP is an agent-facing interface over that real state

This project is not intended to be just a traffic capture database with an MCP wrapper around it.

## High-Level Architecture

The system has three major parts:

1. `mitmproxy` real state
2. a redacted read projection for MCP
3. a native control bridge for state-changing operations

At a high level:

```text
                    Human UI
                   mitmweb/TUI
                        |
                        v
Agent -> MCP tools -> mitmproxy real state
                        |
                        v
              FlowProjectionStore
                        |
                        v
                MCP read responses
```

## Core Principle

If `mitmproxy` has a native concept for an operation, MCP should use that native concept.

Examples:

- `mark_flow` should mark the real mitmproxy flow
- `delete_flow` should delete the real mitmproxy flow
- `clear_captured_flows` should clear the real mitmproxy view/store
- `import_flows` should load flows into the real mitmproxy view/store
- `export_flows` should write flows from the real mitmproxy view/store
- `duplicate_flow` should use real mitmproxy duplication
- `replay_flow` should use real mitmproxy replay
- interception tools should use real mitmproxy interception state

This keeps:

- MCP behavior intuitive
- mitmweb and MCP consistent with each other
- mitmproxy as the single source of truth

## Main Components

### 1. `mitmproxy` real state

`mitmproxy` owns:

- live flows
- request/response state
- markers
- comments
- replay behavior
- interception behavior
- runtime options

Any operation that changes flow state should ultimately be applied here.

### 2. `FlowProjectionStore`

The MCP server should not expose raw mitmproxy objects directly.

Instead, it keeps a projection that is:

- normalized
- redacted
- queryable
- MCP-friendly

This projection exists for several reasons:

- agents need compact JSON-like summaries and details
- redaction must happen before data is exposed to an MCP client
- filtering, pagination, and counts are easier on normalized data
- raw mitmproxy objects are not a good public MCP response shape

Important constraint:

> `FlowProjectionStore` is a read model, not the source of truth

It should be rebuildable from mitmproxy state at any time.

### 3. `MitmproxyController`

State-changing MCP tools do not mutate the projection directly.

They go through `MitmproxyController`, which:

- resolves real mitmproxy flows
- schedules native commands on the mitmproxy event loop
- returns safe MCP-friendly results

This is important because the MCP server thread and the mitmproxy runtime thread are different.

## Sync Model

The projection is synced from mitmproxy view/store signals.

Current mental model:

```text
mitmproxy real state
  -> view/store signals
  -> FlowProjectionStore
  -> MCP read tools
```

and:

```text
MCP write tools
  -> MitmproxyController
  -> mitmproxy real state
```

This means sync works in both directions:

- MCP changes should be reflected in mitmweb
- mitmweb changes should be reflected in MCP

## Why The Projection Still Matters

Even after moving the project to a mitmproxy-native model, the projection is still useful.

Without it, every read tool would need to:

- jump into mitmproxy’s runtime
- resolve real flows
- normalize them on demand
- redact them on demand
- filter and paginate at request time

That would tightly couple every MCP read path to mitmproxy internals and runtime access.

The projection gives us:

- fast reads
- a stable API contract
- a clear privacy boundary
- simpler read logic

## Privacy Model

The project keeps a boundary between:

- raw mitmproxy state, which may contain secrets
- MCP-visible projection data, which should be redacted

Current redaction covers:

- sensitive headers
- sensitive query parameters
- body preview redaction for common secret keys

The idea is:

- agents can inspect useful traffic information
- secrets are reduced before exposure
- real flows still exist in mitmproxy for native actions like replay

## Addon-First Design

This project is intentionally addon-first.

That means:

- the MCP server is embedded inside a running mitmproxy instance
- the canonical runtime path is loading `addon.py`
- the project is not centered around a standalone `stdio` server

Why:

- the real value is controlling a live mitmproxy session
- this keeps agent actions close to native mitmproxy behavior
- it matches the product goal better than a detached standalone process

## Current Tool Philosophy

Read tools:

- read from the projection
- return redacted summaries/details
- should be query-friendly

Write tools:

- act on real mitmproxy state
- should stay aligned with mitmproxy semantics
- should rely on the projection only for later readback, not for the real action

## Current Tool Categories

Read / inspect:

- `list_captured_flows`
- `get_captured_flow`
- `get_flow_count`
- `list_marked_flows`
- `get_intercepted_flows`

State / annotation:

- `mark_flow`
- `unmark_flow`
- `comment_flow`

Interception / live control:

- `set_intercept`
- `resume_flow`
- `resume_all`
- `kill_flow`

Flow lifecycle / mutation:

- `import_flows`
- `export_flows`
- `duplicate_flow`
- `replay_flow`
- `revert_flow`
- `delete_flow`
- `clear_captured_flows`

## Important Behavioral Notes

### Importing flows

`import_flows`:

- accepts HAR files and mitmproxy flow dump files
- validates the file extension before import
- validates the file content format before import
- loads flows into real mitmproxy state, not only into the projection

This matters because imported flows should behave like normal flows already present in mitmproxy:

- they should appear in mitmweb
- they should be queryable through MCP read tools
- they should be available to native tools like mark, comment, duplicate, replay, and delete

### Exporting flows

`export_flows`:

- writes flows from real mitmproxy state to disk
- supports HAR export and mitmproxy flow dump export
- uses mitmproxy view selectors such as `@all`, `@marked`, and `@focus`

This matters because export should reflect the real flows currently present in mitmproxy, not a separate MCP-only representation.

### Duplicate vs replay

`duplicate_flow`:

- creates another real flow in mitmproxy
- does not send traffic

`replay_flow`:

- replays the current real flow through mitmproxy
- follows mitmproxy replay semantics

### Interception can happen twice

If an intercept filter is broad, for example it matches both request and response, the same flow may be intercepted twice:

- once on the request
- once again on the response

In that situation, the flow may need two resumes.

This is normal mitmproxy behavior, not necessarily a bug.

## Current Code Layout

- [addon.py](/Users/matte/Desktop/mitmproxy-MCP/addon.py)
  Thin top-level addon entry point.
- [core/addon.py](/Users/matte/Desktop/mitmproxy-MCP/core/addon.py)
  Main mitmproxy addon, runtime wiring, signal subscriptions, projection sync.
- [core/control.py](/Users/matte/Desktop/mitmproxy-MCP/core/control.py)
  Native mitmproxy control bridge for MCP write tools.
- [core/store.py](/Users/matte/Desktop/mitmproxy-MCP/core/store.py)
  `FlowProjectionStore` read model.
- [core/server.py](/Users/matte/Desktop/mitmproxy-MCP/core/server.py)
  MCP tool definitions.
- [core/models.py](/Users/matte/Desktop/mitmproxy-MCP/core/models.py)
  Flow summary/detail models.
- [core/privacy.py](/Users/matte/Desktop/mitmproxy-MCP/core/privacy.py)
  Redaction logic.
- [core/config.py](/Users/matte/Desktop/mitmproxy-MCP/core/config.py)
  Environment-backed settings.
- [core/runtime.py](/Users/matte/Desktop/mitmproxy-MCP/core/runtime.py)
  Embedded MCP runtime startup.
- [core/markers.py](/Users/matte/Desktop/mitmproxy-MCP/core/markers.py)
  Marker normalization.

## Why This Direction Is Good

This direction makes the project:

- more coherent
- closer to mitmproxy itself
- easier to reason about
- safer from a product perspective

Most importantly, it answers the user expectation correctly:

if an agent marks, deletes, comments, clears, replays, or intercepts a flow, it should be operating the real tool, not a shadow copy.

## Future Directions

Likely next areas:

- runtime option discovery and control
- flow field editing
- more native mitmproxy actions
- automated tests
- richer client examples and docs
