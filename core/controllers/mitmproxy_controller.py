from __future__ import annotations

from mitmproxy.master import Master

from .flows import FlowController
from .options import OptionController
from .transfer import TransferController


class MitmproxyController(FlowController, OptionController, TransferController):
    def __init__(self) -> None:
        self._master: Master | None = None

    def attach_master(self, master: Master) -> None:
        self._master = master

    def detach_master(self) -> None:
        self._master = None

    def _require_master(self) -> Master:
        if self._master is None:
            raise RuntimeError("mitmproxy is not running, so active flow commands are unavailable.")

        return self._master
