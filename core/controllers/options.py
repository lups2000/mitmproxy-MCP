from __future__ import annotations

from concurrent.futures import Future
from typing import Any

from mitmproxy import optmanager


class OptionController:
    _SET_OPTION_BLACKLIST = {
        "mode",
        "listen_host",
        "listen_port",
        "confdir",
        "certs",
        "cert_passphrase",
        "client_certs",
        "ssl_insecure",
        "ssl_verify_upstream_trusted_ca",
        "ssl_verify_upstream_trusted_confdir",
        "allow_hosts",
        "ignore_hosts",
    }

    def list_options(self, search: str | None = None) -> list[dict[str, Any]]:
        master = self._require_master()
        result: Future[list[dict[str, Any]]] = Future()

        def _list_options() -> None:
            try:
                keys = list(master.options.keys())
                if search:
                    normalized_search = search.lower()
                    keys = [key for key in keys if normalized_search in key.lower()]

                dumped = optmanager.dump_dicts(master.options, keys)
                result.set_result(
                    [
                        {
                            "name": name,
                            "type": metadata["type"],
                            "default": metadata["default"],
                            "value": metadata["value"],
                            "help": metadata["help"],
                            "choices": metadata["choices"],
                        }
                        for name, metadata in dumped.items()
                    ]
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_list_options)
        return result.result(timeout=5)

    def get_option(self, name: str) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _get_option() -> None:
            try:
                if name not in master.options.keys():
                    raise ValueError(f"Unknown option: {name}")

                metadata = optmanager.dump_dicts(master.options, [name])[name]
                result.set_result(
                    {
                        "name": name,
                        "type": metadata["type"],
                        "default": metadata["default"],
                        "value": metadata["value"],
                        "help": metadata["help"],
                        "choices": metadata["choices"],
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_get_option)
        return result.result(timeout=5)

    def set_option(self, name: str, value: Any) -> dict[str, Any]:
        master = self._require_master()
        result: Future[dict[str, Any]] = Future()

        def _set_option() -> None:
            try:
                if name not in master.options.keys():
                    raise ValueError(f"Unknown option: {name}")

                if name in self._SET_OPTION_BLACKLIST:
                    raise ValueError(f"Setting option '{name}' is not allowed through MCP.")

                specs = self._build_option_specs(name, value)
                master.options.set(*specs)

                metadata = optmanager.dump_dicts(master.options, [name])[name]
                result.set_result(
                    {
                        "name": name,
                        "type": metadata["type"],
                        "default": metadata["default"],
                        "value": metadata["value"],
                        "help": metadata["help"],
                        "choices": metadata["choices"],
                    }
                )
            except Exception as exc:
                result.set_exception(exc)

        master.event_loop.call_soon_threadsafe(_set_option)
        return result.result(timeout=5)

    def _build_option_specs(self, name: str, value: Any) -> list[str]:
        if isinstance(value, bool):
            return [f"{name}={'true' if value else 'false'}"]

        if value is None:
            return [name]

        if isinstance(value, int):
            return [f"{name}={value}"]

        if isinstance(value, str):
            return [f"{name}={value}"]

        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return [f"{name}={item}" for item in value]

        raise ValueError(
            f"Unsupported value for option '{name}'. "
            "Supported value types are bool, int, str, null, and list[str]."
        )
