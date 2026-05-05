from core.store import FlowProjectionStore, _preview_bytes
from tests.helpers import make_http_flow


def test_preview_bytes_handles_none():
    assert _preview_bytes(None) == ""


def test_preview_bytes_limits_bytes():
    assert _preview_bytes(b"abcdef", limit=3) == "abc"


def test_add_and_get_flow(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    detail = store.add_from_mitmproxy_flow(sample_flow)
    fetched = store.get_flow(detail.id)
    assert fetched is not None
    assert fetched["host"] == "example.com"
    assert fetched["request_headers"]["Authorization"] == "[REDACTED]"
    assert fetched["query"].endswith("token=[REDACTED]")


def test_replace_existing_flow_preserves_single_entry(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    store.add_from_mitmproxy_flow(sample_flow)
    sample_flow.comment = "updated"
    store.add_from_mitmproxy_flow(sample_flow)
    flows = store.list_flows()
    assert len(flows) == 1
    assert flows[0]["comment"] == "updated"


def test_max_flows_evicts_oldest():
    store = FlowProjectionStore(max_flows=2)
    first = make_http_flow(url="https://a.example.com/a")
    second = make_http_flow(url="https://b.example.com/b")
    third = make_http_flow(url="https://c.example.com/c")
    store.add_from_mitmproxy_flow(first)
    store.add_from_mitmproxy_flow(second)
    store.add_from_mitmproxy_flow(third)
    flows = store.list_flows(limit=10)
    hosts = [flow["host"] for flow in flows]
    assert "a.example.com" not in hosts
    assert hosts == ["b.example.com", "c.example.com"]


def test_list_flows_filters(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    flow1 = sample_flow
    flow2 = make_http_flow(url="http://other.test/err", method="POST", status_code=500, marked=":red_circle:", intercepted=True)
    store.add_from_mitmproxy_flow(flow1)
    store.add_from_mitmproxy_flow(flow2)

    assert len(store.list_flows(marked=True)) == 1
    assert len(store.list_flows(intercepted=True)) == 1
    assert len(store.list_flows(error_only=True)) == 1
    assert len(store.list_flows(host="example.com")) == 1
    assert len(store.list_flows(method="post")) == 1
    assert len(store.list_flows(status_code=500)) == 1
    assert len(store.list_flows(path_contains="err")) == 1


def test_pagination(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    store.add_from_mitmproxy_flow(sample_flow)
    store.add_from_mitmproxy_flow(make_http_flow(url="https://two.example.com/two"))
    paged = store.list_flows(limit=1, offset=1)
    assert len(paged) == 1
    assert paged[0]["host"] == "two.example.com"


def test_get_flow_count(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    store.add_from_mitmproxy_flow(sample_flow)
    assert store.get_flow_count() == 1


def test_remove_flow_and_missing_get(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    detail = store.add_from_mitmproxy_flow(sample_flow)
    store.remove_flow(detail.id)
    assert store.get_flow(detail.id) is None


def test_replace_from_mitmproxy_flows_truncates():
    store = FlowProjectionStore(max_flows=2)
    store.replace_from_mitmproxy_flows(
        [
            make_http_flow(url="https://one.example.com/1"),
            make_http_flow(url="https://two.example.com/2"),
            make_http_flow(url="https://three.example.com/3"),
        ]
    )
    flows = store.list_flows(limit=10)
    assert [flow["host"] for flow in flows] == ["two.example.com", "three.example.com"]


def test_build_redacted_url_non_default_port(sample_flow):
    store = FlowProjectionStore(max_flows=10)
    sample_flow.request.port = 8443
    detail = store.add_from_mitmproxy_flow(sample_flow)
    assert ":8443" in detail.url
