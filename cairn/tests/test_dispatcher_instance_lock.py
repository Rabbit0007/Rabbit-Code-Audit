from __future__ import annotations

from types import SimpleNamespace

import pytest

from cairn.dispatcher.runtime.instance_lock import DispatcherAlreadyRunning, DispatcherInstanceLock


def test_dispatcher_instance_lock_blocks_second_holder(tmp_path):
    config_path = tmp_path / "dispatch.yaml"
    config_path.write_text("server: http://127.0.0.1:8765\n", encoding="utf-8")
    config = SimpleNamespace(server="http://127.0.0.1:8765")

    first = DispatcherInstanceLock.for_config(config_path, config)
    second = DispatcherInstanceLock.for_config(config_path, config)

    first.acquire()
    try:
        with pytest.raises(DispatcherAlreadyRunning):
            second.acquire()
    finally:
        first.release()

    second.acquire()
    second.release()
