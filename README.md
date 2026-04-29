# mitmproxy MCP

`mitmproxy-mcp` is an MCP server embedded inside `mitmproxy`.

The project goal is not just "capture traffic and expose it over MCP". The goal is:

> make `mitmproxy` available to agents the same way `mitmweb` makes it available to humans.

That means:

- `mitmproxy` is the source of truth
- MCP tools act on real `mitmproxy` state
- the MCP server exposes a redacted read model for safe inspection
- changes made from MCP are reflected in `mitmproxy`
- changes made from `mitmproxy` are reflected in MCP

## What This Server Does

This server lets an MCP client:

- inspect HTTP flows currently present in `mitmproxy`
- filter, count, and fetch detailed flow data
- mark and comment flows
- duplicate, replay, delete, clear, revert, kill, and resume flows
- configure interception rules and inspect intercepted flows

It is intentionally **addon-first**:

- run it by loading the addon into `mitmproxy` / `mitmweb` / `mitmdump`
- do not run it as a standalone `stdio` MCP server

## Architecture

The current architecture has three important parts:

### 1. mitmproxy real state

`mitmproxy` owns the real flows, interception state, replay behavior, comments, markers, and runtime options.

All write tools are designed to operate on this real state.

### 2. FlowProjectionStore

The MCP server does **not** expose raw `mitmproxy` flow objects directly.

Instead, it maintains a redacted projection:

- normalized summaries and details
- redacted headers
- redacted query parameters
- redacted body previews
- filtering and pagination support

This projection is a **read model**, not a second source of truth.

### 3. MitmproxyController

State-changing MCP tools go through a controller that calls native `mitmproxy` commands on the real event loop.

Examples:

- `mark_flow` -> native `flow.mark`
- `delete_flow` -> native `view.flows.remove`
- `clear_captured_flows` -> native `view.clear`
- `duplicate_flow` -> native `view.flows.duplicate`
- `replay_flow` -> native `replay.client`

### Sync model

The MCP projection is kept in sync from `mitmproxy`'s real view/store signals.

So the effective model is:

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

## Requirements

- Python `>= 3.12`
- `uv`

Dependencies:

- `mitmproxy >= 12.2.1`
- `mcp >= 1.27.0`

## Setup

Create the environment and install dependencies:

```bash
uv sync
```

If you prefer to activate the local environment:

```bash
source .venv/bin/activate
```

## Running The Server

### Recommended: mitmweb

This is the best mode for development because you can use both:

- `mitmweb` as the human UI
- MCP as the agent UI

Start it with:

```bash
.venv/bin/mitmweb -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

By default:

- proxy listens on `127.0.0.1:8080`
- `mitmweb` listens on `http://127.0.0.1:8081`
- MCP listens on `127.0.0.1:8000`

### mitmdump

If you want a headless proxy plus MCP server:

```bash
.venv/bin/mitmdump -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

## MCP Transports

Supported MCP transports:

- `streamable-http`
- `sse`

Not supported:

- standalone `stdio`

### streamable-http

Default and recommended.

Run with:

```bash
.venv/bin/mitmweb -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

Connect your MCP client to:

```text
http://127.0.0.1:8000/mcp
```

### SSE

Run with:

```bash
.venv/bin/mitmweb -s addon.py --set mcp_transport=sse --set mcp_port=8000
```

Connect your MCP client to:

```text
http://127.0.0.1:8000/sse
```

Note:

- some SSE clients internally use the companion messages path managed by the MCP SDK
- the MCP server exposes that automatically
- the client typically only needs the main SSE endpoint

## Using MCP Clients

This project works best with MCP clients that support HTTP-based transports:

- clients that support `streamable-http`
- clients that support `sse`


### Important note about stdio-only clients

This project does **not** currently expose a standalone `stdio` server.

So clients that only support `stdio` are not the right fit unless they also support:

- `streamable-http`
- `sse`

## Configuration

You can configure the project through environment variables.

See `.env.example`:

```dotenv
MITMPROXY_MCP_PROXY_HOST=127.0.0.1
MITMPROXY_MCP_PROXY_PORT=8080

MITMPROXY_MCP_MCP_HOST=127.0.0.1
MITMPROXY_MCP_MCP_PORT=8000
MITMPROXY_MCP_MCP_TRANSPORT=streamable-http

MITMPROXY_MCP_MAX_FLOWS=1000
MITMPROXY_MCP_BODY_PREVIEW_LIMIT=200

MITMPROXY_MCP_REDACTION_ENABLED=true
MITMPROXY_MCP_REDACT_HEADERS=true
MITMPROXY_MCP_REDACT_QUERY_PARAMS=true
MITMPROXY_MCP_REDACT_BODY_PREVIEWS=true
```

### Main settings

- `MITMPROXY_MCP_PROXY_HOST`
- `MITMPROXY_MCP_PROXY_PORT`
- `MITMPROXY_MCP_MCP_HOST`
- `MITMPROXY_MCP_MCP_PORT`
- `MITMPROXY_MCP_MCP_TRANSPORT`
- `MITMPROXY_MCP_MAX_FLOWS`
- `MITMPROXY_MCP_BODY_PREVIEW_LIMIT`

### Redaction settings

- `MITMPROXY_MCP_REDACTION_ENABLED`
- `MITMPROXY_MCP_REDACT_HEADERS`
- `MITMPROXY_MCP_REDACT_QUERY_PARAMS`
- `MITMPROXY_MCP_REDACT_BODY_PREVIEWS`

## Privacy And Redaction

The MCP read model is redacted by default.

Current redaction behavior includes:

- sensitive headers such as `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, API-key style headers
- sensitive query parameters such as `token`, `access_token`, `refresh_token`, `api_key`, `password`, `secret`, `session`
- basic JSON body-preview redaction for common secret keys

The purpose is:

- keep `mitmproxy`'s raw state available internally
- expose safer inspection data to agents

## Current Tools

### Read / inspect

- `list_captured_flows(limit=20, offset=0, error_only=False, host=None, method=None, status_code=None, path_contains=None)`
  List redacted flow summaries currently present in `mitmproxy`'s view.
- `get_captured_flow(flow_id)`
  Get one redacted detailed flow by `mitmproxy` flow id.
- `get_flow_count(marked=None, error_only=False, host=None, method=None, status_code=None, path_contains=None)`
  Count flows matching filters.
- `list_marked_flows(limit=20, offset=0)`
  List flows with any `mitmproxy` marker set.
- `get_intercepted_flows(limit=20, offset=0)`
  List flows currently intercepted.

### Marking / notes

- `mark_flow(flow_id, marker="red")`
  Set a real `mitmproxy` marker.
- `unmark_flow(flow_id)`
  Remove a marker from a real flow.
- `comment_flow(flow_id, comment)`
  Set or replace the real `mitmproxy` comment. Pass an empty string to clear it.

### Interception / live control

- `set_intercept(flow_filter, active=True)`
  Enable or disable interception using a real `mitmproxy` filter expression.
- `resume_flow(flow_id)`
  Resume one intercepted flow.
- `resume_all()`
  Resume all currently intercepted HTTP flows.
- `kill_flow(flow_id)`
  Kill one intercepted/live flow.

### Flow lifecycle / mutation

- `duplicate_flow(flow_id)`
  Duplicate a real flow in the `mitmproxy` view without sending it.
- `replay_flow(flow_id)`
  Replay a real flow using native `mitmproxy` client replay.
- `revert_flow(flow_id)`
  Revert a modified flow to its last backed-up `mitmproxy` state.
- `delete_flow(flow_id)`
  Delete one real flow from the `mitmproxy` view/store.
- `clear_captured_flows()`
  Clear all real flows from the `mitmproxy` view/store.

## Current Status

The project currently has:

- addon-first architecture
- native `mitmproxy` write/control tools
- redacted read projection
- `mitmweb` <-> MCP synchronization
- `streamable-http` and `sse` support

What is still missing compared with a larger production surface:

- runtime option discovery tools like `list_options`, `get_option`, `set_option`
- flow field editing tools
- automated tests
- fuller README examples for specific MCP hosts

