from __future__ import annotations

import asyncio

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from mitm_addon import addons as mitm_addons
from server import mcp


async def run_combined() -> None:
    opts = options.Options(listen_host="127.0.0.1", listen_port=8080)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(*mitm_addons)

    async with asyncio.TaskGroup() as task_group:
        task_group.create_task(master.run())
        task_group.create_task(mcp.run_streamable_http_async())


if __name__ == "__main__":
    asyncio.run(run_combined())
