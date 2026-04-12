from __future__ import annotations

import asyncio

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .addon import addons as mitm_addons
from .config import settings
from .server import mcp


async def run_combined() -> None:
    opts = options.Options(listen_host=settings.proxy_host, listen_port=settings.proxy_port)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(*mitm_addons)

    async with asyncio.TaskGroup() as task_group:
        task_group.create_task(master.run())
        task_group.create_task(mcp.run_streamable_http_async())


def main() -> None:
    asyncio.run(run_combined())
