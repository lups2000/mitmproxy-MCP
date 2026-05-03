from mcp.server.fastmcp import FastMCP

from ..controllers import mitmproxy_controller


def register_option_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    def list_options(search: str | None = None) -> list[dict]:
        """List mitmproxy runtime options from the real running instance.

        Use search to filter option names by substring when you are looking for
        specific areas such as intercept, mode, tls, or upstream.
        """
        return mitmproxy_controller.list_options(search)

    @mcp.tool()
    def get_option(name: str) -> dict:
        """Get one mitmproxy runtime option by exact name."""
        return mitmproxy_controller.get_option(name)

    @mcp.tool()
    def set_option(name: str, value: bool | int | str | list[str] | None) -> dict:
        """Set one mitmproxy runtime option by exact name.

        This uses mitmproxy's native option parsing and updates the real running
        instance. The following high-risk options are intentionally blocked:
        mode, listen_host, listen_port, ssl_insecure,
        ssl_verify_upstream_trusted_ca, ssl_verify_upstream_trusted_confdir,
        client_certs, certs, cert_passphrase, confdir, allow_hosts,
        ignore_hosts.
        """
        return mitmproxy_controller.set_option(name, value)
