# mitmproxy MCP

This project is a Python-based MCP server for inspecting HTTP traffic captured through mitmproxy.

## Roadmap

### M1 Foundation Refactor

Goal: turn the current prototype scripts into a small, coherent package.

Scope:
- move code into a package, for example `mitmproxy_mcp/`
- split responsibilities into:
  - `config.py`
  - `models.py`
  - `store.py`
  - `addon.py`
  - `server.py`
  - `runtime.py`
- remove hardcoded runtime values from the current runner
- define a central settings object for proxy host/port, MCP host/port, transport, retention limits, and preview sizes

Success criteria:
- same behavior as today
- same manual test still works
- codebase is easier to extend

### M2 Better Flow Models

Goal: define clean data contracts for captured traffic.

Scope:
- separate `FlowSummary` from `FlowDetail`
- keep normalization in one place
- make list tools return summaries instead of full records
- keep detailed headers/body previews in detail views only
- add explicit truncation metadata where useful

Success criteria:
- `list_flows` is compact and useful
- `get_flow` is richer and more structured
- normalized models feel deliberate, not accidental

### M3 Queryable Store

Goal: make the in-memory store behave like a real repository.

Scope:
- filtering by host, method, status code, and path substring
- limit/offset or similar pagination
- recent-first ordering
- retention controls for max flow count and body preview size

Success criteria:
- an agent can find interesting flows without dumping everything

### M4 Privacy And Redaction

Goal: avoid exposing secrets to MCP clients by default.

Scope:
- redact sensitive headers like `authorization`, `cookie`, `set-cookie`, and common API key headers
- redact sensitive query parameters
- basic body redaction for obvious secrets
- configurable redaction policy with safe defaults

Success criteria:
- sensitive data is masked in list/detail tools by default
- redaction behavior is testable and configurable

### M5 Improved MCP Tool Surface

Goal: make the server genuinely useful to an agent.

Scope:
- inspection tools such as:
  - `list_flows`
  - `get_flow`
  - `clear_flows`
  - `find_flows`
  - `get_recent_flows`
  - `get_flow_request`
  - `get_flow_response`
- return compact summaries from list/search tools
- keep detail tools focused and predictable

Success criteria:
- common traffic investigation tasks can be done with a few tool calls

### M6 Stronger Mitmproxy Integration

Goal: behave more like a true mitmproxy-native extension.

Scope:
- decide which lifecycle events to capture, such as completed responses and errored flows
- improve logging and runtime behavior inside mitmproxy
- reuse mitmproxy features where practical
- decide the official startup model

Success criteria:
- runtime behavior is intentional and documented
- edge cases like failed responses are handled explicitly

### M7 Transport And Client Compatibility

Goal: make it easy to use from real MCP hosts.

Scope:
- keep one transport solid first
- then add or configure:
  - `stdio`
  - `sse`
  - streamable HTTP
- document exact connection instructions for common clients
- make transport selectable through config

Success criteria:
- at least two transport modes work reliably
- docs show exactly how to connect

### M8 Packaging And CLI

Goal: make the project installable and runnable like a real tool.

Scope:
- define package entry points in `pyproject.toml`
- add CLI commands such as `mitmproxy-mcp`
- clean README with install, run, and connect examples
- support addon loading in a more standard mitmproxy way if appropriate

Success criteria:
- a new user can install and run it without reading source code

### M9 Testing And Hardening

Goal: make changes safe and confidence-building.

Scope:
- unit tests for normalization, filtering, redaction, and tool outputs
- integration tests for capturing a flow and inspecting it via MCP
- runtime tests for startup, shutdown, and empty-store behavior

Success criteria:
- core functionality is covered by automated tests
- regressions become harder to introduce

### M10 Advanced Features

Goal: close the gap with richer implementations once the core is stable.

Potential scope:
- replay flow
- delete one flow
- export flows
- interception control
- runtime config tools
- richer search and analytics

## Priority Order

1. `M1 Foundation Refactor`
2. `M2 Better Flow Models`
3. `M3 Queryable Store`
4. `M4 Privacy And Redaction`
5. `M5 Improved MCP Tool Surface`
6. `M6 Stronger Mitmproxy Integration`
7. `M7 Transport And Client Compatibility`
8. `M8 Packaging And CLI`
9. `M9 Testing And Hardening`
10. `M10 Advanced Features`

## Working Principles

- Do not optimize for feature count before data model quality.
- Do not expose raw secrets to MCP clients.
- Do not let list tools become noisy dumps.
- Prefer summary tools for navigation and detail tools for drill-down.
- Reuse mitmproxy’s model where it helps, not just its events.
- Keep every milestone manually testable.
