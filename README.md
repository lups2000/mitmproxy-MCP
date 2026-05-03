# mitmproxy MCP

`mitmproxy-mcp` is an MCP server embedded inside `mitmproxy`.

The goal of this project is to make `mitmproxy` available to agents the way `mitmweb` makes it available to humans.

If you want the architecture and design rationale, see [docs/design.md](/Users/matte/Desktop/mitmproxy-MCP/docs/design.md).

## What This Repo Is

This project gives an MCP client access to live `mitmproxy` traffic and controls.

Current capabilities include:

- inspect HTTP flows currently present in `mitmproxy`
- filter, count, and fetch detailed flow data
- mark and comment flows
- import flows from HAR files or mitmproxy flow dumps
- export flows to HAR files or mitmproxy flow dumps
- duplicate, replay, revert, delete, clear, kill, and resume flows
- configure interception rules and inspect intercepted flows
- inspect and update mitmproxy runtime options

This project is intentionally **addon-first**:

- run it by loading the addon into `mitmproxy`, `mitmweb`, or `mitmdump`
- do not run it as a standalone `stdio` MCP server

## Quick Start

Requirements:

- Python `>= 3.12`
- `uv`

Install dependencies:

```bash
uv sync
```

If you want to activate the local virtual environment:

```bash
source .venv/bin/activate
```

## Run The Server

### Recommended: mitmweb

This is the best development mode because you get:

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

### Headless: mitmdump

```bash
.venv/bin/mitmdump -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

## MCP Transports

Supported transports:

- `streamable-http`
- `sse`

Not supported:

- standalone `stdio`

### streamable-http

Recommended default.

Endpoint:

```text
http://127.0.0.1:8000/mcp
```

### SSE

Endpoint:

```text
http://127.0.0.1:8000/sse
```

## Connect Your AI Client

This project works best with clients that support HTTP-based MCP transports.

### First: choose the transport

In most cases, use:

- `streamable-http` at `http://127.0.0.1:8000/mcp`

If your client prefers SSE, use:

- `sse` at `http://127.0.0.1:8000/sse`

### Important note about stdio-only clients

This project does not currently expose a standalone `stdio` server.

So clients that only support `stdio` are not the right fit unless they also support:

- `streamable-http`
- `sse`

### OpenCode

Example `opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mitmproxy-mcp": {
      "type": "remote",
      "url": "http://127.0.0.1:8000/mcp",
      "enabled": true
    }
  }
}
```

For SSE:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mitmproxy-mcp": {
      "type": "remote",
      "url": "http://127.0.0.1:8000/sse",
      "enabled": true
    }
  }
}
```

### Claude Code

For `streamable-http`:

```bash
claude mcp add --transport http mitmproxy-mcp http://127.0.0.1:8000/mcp
```

For `sse`:

```bash
claude mcp add --transport sse mitmproxy-mcp http://127.0.0.1:8000/sse
```

Useful follow-up commands:

```bash
claude mcp list
claude mcp get mitmproxy-mcp
```

### Codex

Codex supports MCP servers over URL.

For `streamable-http`:

```bash
codex mcp add mitmproxy-mcp --url http://127.0.0.1:8000/mcp
```

Verify it with:

```bash
codex mcp list
```

## Configuration

The project can be configured through environment variables.

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

Main settings:

- `MITMPROXY_MCP_PROXY_HOST`
- `MITMPROXY_MCP_PROXY_PORT`
- `MITMPROXY_MCP_MCP_HOST`
- `MITMPROXY_MCP_MCP_PORT`
- `MITMPROXY_MCP_MCP_TRANSPORT`
- `MITMPROXY_MCP_MAX_FLOWS`
- `MITMPROXY_MCP_BODY_PREVIEW_LIMIT`

Redaction settings:

- `MITMPROXY_MCP_REDACTION_ENABLED`
- `MITMPROXY_MCP_REDACT_HEADERS`
- `MITMPROXY_MCP_REDACT_QUERY_PARAMS`
- `MITMPROXY_MCP_REDACT_BODY_PREVIEWS`

## Privacy And Redaction

The MCP read model is redacted by default.

Current redaction behavior includes:

- sensitive headers such as `authorization`, `cookie`, `set-cookie`, `proxy-authorization`, and API-key style headers
- sensitive query parameters such as `token`, `access_token`, `refresh_token`, `api_key`, `password`, `secret`, and `session`
- basic JSON body-preview redaction for common secret keys

## Available Tools

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

### Options

- `list_options(search=None)`
  List mitmproxy runtime options from the real running instance. Use `search` to narrow by name.
- `get_option(name)`
  Get one mitmproxy runtime option by exact name.
- `set_option(name, value)`
  Set one mitmproxy runtime option by exact name using mitmproxy's native option parsing. Blocked options: `mode`, `listen_host`, `listen_port`, `ssl_insecure`, `ssl_verify_upstream_trusted_ca`, `ssl_verify_upstream_trusted_confdir`, `client_certs`, `certs`, `cert_passphrase`, `confdir`, `allow_hosts`, `ignore_hosts`.

### Flow lifecycle / mutation

- `import_flows(path)`
  Import flows from a HAR file or mitmproxy flow dump into the real `mitmproxy` view/store.
- `export_flows(path, flow_spec="@all")`
  Export flows from the real `mitmproxy` view/store into a HAR file or mitmproxy flow dump. The output format is selected from the destination filename. `flow_spec` can be `@all`, `@marked`, `@focus`, or another mitmproxy flow selector/filter.
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
