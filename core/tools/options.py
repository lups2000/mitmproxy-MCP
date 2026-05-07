from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller


def register_option_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def list_options(search: str | None = None) -> list[dict]:
        """List mitmproxy runtime options from the real running instance.

        This reads real mitmproxy runtime state and does not modify any option.
        Use this first when you need to discover available option names, current
        values, defaults, metadata, or allowed choices.
        search filters option names by substring, which is useful for areas such as
        intercept, tls, upstream, proxy, or mode.
        """
        return mitmproxy_controller.list_options(search)

    @mcp.tool()
    def get_option(name: str) -> dict:
        """Get one mitmproxy runtime option by exact name.

        This reads real mitmproxy runtime state and returns metadata plus the
        current value for one option.
        Use this after list_options when you want the precise state of a single
        option before deciding whether to change it.
        name must be the exact mitmproxy option name.
        """
        return mitmproxy_controller.get_option(name)

    @mcp.tool()
    def set_option(name: str, value: bool | int | str | list[str] | None) -> dict:
        """Set one mitmproxy runtime option by exact name.

        This changes real mitmproxy runtime state using mitmproxy's native option
        parsing and validation.
        Use this when you want to change runtime behavior such as interception or
        other allowed options on the live proxy instance.
        name must be the exact mitmproxy option name. value must be a bool, int,
        str, list[str], or null depending on the target option.
        The following higher-risk options are intentionally blocked: mode,
        listen_host, listen_port, ssl_insecure,
        ssl_verify_upstream_trusted_ca, ssl_verify_upstream_trusted_confdir,
        client_certs, certs, cert_passphrase, confdir, allow_hosts, ignore_hosts.
        """
        return mitmproxy_controller.set_option(name, value)
