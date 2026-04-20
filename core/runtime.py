from __future__ import annotations

import asyncio

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .addon import addons as mitm_addons
from .config import settings


async def run_mitmproxy() -> None:
    opts = options.Options(
        listen_host=settings.proxy_host,
        listen_port=settings.proxy_port,
    )
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(*mitm_addons)
    master.options.update(
        mcp_host=settings.mcp_host,
        mcp_port=settings.mcp_port,
        mcp_transport=settings.mcp_transport,
    )
    await master.run()


def main() -> None:
    asyncio.run(run_mitmproxy())
