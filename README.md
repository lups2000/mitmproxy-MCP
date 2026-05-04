# mitmproxy MCP

`mitmproxy-mcp` is an MCP server embedded inside `mitmproxy`.

The goal is simple:

> make `mitmproxy` available to agents the way `mitmweb` makes it available to humans

Architecture and rationale live in [docs/design.md](/Users/matte/Desktop/mitmproxy-MCP/docs/design.md).

## What It Offers

This MCP gives an agent a live interface over a running `mitmproxy` instance.

Core capabilities:

- inspect captured HTTP flows
- filter, count, and fetch detailed flow data
- mark and comment flows
- intercept, resume, kill, replay, duplicate, revert, delete, and clear flows
- import and export HAR / mitmproxy dump files
- inspect and update mitmproxy runtime options

Important product constraint:

- `mitmproxy` is the source of truth
- this project is **addon-first**
- it is **not** a standalone `stdio` MCP server

## Tool Overview (19 Tools)

### Read / inspect

- `list_captured_flows`: browse redacted flow summaries with filtering and pagination
- `get_captured_flow`: inspect one flow in detail
- `get_flow_count`: count flows matching the main filters
- `list_marked_flows`: show flows that currently have a mitmproxy marker
- `get_intercepted_flows`: show flows that are currently intercepted

### Mark / annotate

- `mark_flow`: add a colored mitmproxy marker to a flow
- `unmark_flow`: remove the current marker
- `comment_flow`: attach or replace a mitmproxy comment

### Intercept / control

- `set_intercept`: enable or disable interception with a mitmproxy filter expression
- `resume_flow`: resume one intercepted flow
- `resume_all`: resume all intercepted flows
- `kill_flow`: kill one live/intercepted flow

### Options

- `list_options`: discover mitmproxy runtime options
- `get_option`: inspect one option with its current value and metadata
- `set_option`: update one allowed mitmproxy runtime option

### Transfer / mutate

- `import_flows`: load HAR files or mitmproxy dump files into the real mitmproxy view
- `export_flows`: save flows to HAR or mitmproxy dump files
- `duplicate_flow`: create a second real flow without sending traffic
- `replay_flow`: replay the current real flow through mitmproxy
- `revert_flow`: revert a modified flow to its backup state
- `delete_flow`: remove one flow from mitmproxy
- `clear_captured_flows`: remove all flows from mitmproxy

## Quick Start

Requirements:

- Python `>= 3.12`
- `uv`

Install:

```bash
uv sync
```

Optional virtualenv activation:

```bash
source .venv/bin/activate
```

Run with `mitmweb`:

```bash
.venv/bin/mitmweb -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

You can also use:

- `mitmproxy` for the interactive terminal UI
- `mitmdump` for headless mode

Example:

```bash
.venv/bin/mitmproxy -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

Headless:

```bash
.venv/bin/mitmdump -s addon.py --set mcp_transport=streamable-http --set mcp_port=8000
```

Default endpoints:

- proxy: `127.0.0.1:8080`
- mitmweb: `http://127.0.0.1:8081`
- MCP streamable HTTP: `http://127.0.0.1:8000/mcp`
- MCP SSE: `http://127.0.0.1:8000/sse`

## Connect A Client

Supported transports:

- `streamable-http` (recommended)
- `sse`

Not supported:

- standalone `stdio`

### OpenCode

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

For SSE, replace the URL with `http://127.0.0.1:8000/sse`.

### Claude Code

```bash
claude mcp add --transport http mitmproxy-mcp http://127.0.0.1:8000/mcp
```

For SSE:

```bash
claude mcp add --transport sse mitmproxy-mcp http://127.0.0.1:8000/sse
```

### Codex

```bash
codex mcp add mitmproxy-mcp --url http://127.0.0.1:8000/mcp
```

Verify:

```bash
codex mcp list
```

## Configuration

Environment variables are supported through `.env`.

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

See `.env.example` for actual values.

## Privacy

The MCP read model is redacted by default.

Current redaction includes:

- sensitive headers
- sensitive query parameters
- secret-like fields in body previews

## Option Safety

`set_option` intentionally currently blocks these higher-risk options:

- `mode`
- `listen_host`
- `listen_port`
- `ssl_insecure`
- `ssl_verify_upstream_trusted_ca`
- `ssl_verify_upstream_trusted_confdir`
- `client_certs`
- `certs`
- `cert_passphrase`
- `confdir`
- `allow_hosts`
- `ignore_hosts`
