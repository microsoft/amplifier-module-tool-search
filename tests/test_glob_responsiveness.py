"""Slow filesystem operations must not block input or cancellation processing."""

import asyncio
import threading
from pathlib import Path

import pytest

from amplifier_module_tool_search.glob import GlobTool


@pytest.mark.asyncio
async def test_slow_glob_keeps_event_loop_responsive(tmp_path, monkeypatch):
    (tmp_path / "answer.txt").write_text("saved")
    entered, release = threading.Event(), threading.Event()
    original = Path.glob

    def slow_glob(path, pattern):
        entered.set()
        release.wait(1)
        yield from original(path, pattern)

    monkeypatch.setattr(Path, "glob", slow_glob)
    task = asyncio.create_task(
        GlobTool({"working_dir": str(tmp_path)}).execute({"path": str(tmp_path), "pattern": "*.txt"})
    )
    try:
        await asyncio.to_thread(entered.wait, 2)
        # An input/control coroutine must run while the filesystem is blocked.
        assert not task.done(), "The tool monopolized the event loop until the filesystem returned"
    finally:
        release.set()
        result = await task
    assert result.success
    assert [row["path"] for row in result.output["matches"]] == [str(tmp_path / "answer.txt")]


@pytest.mark.asyncio
async def test_cancelled_glob_stops_consuming_results(tmp_path, monkeypatch):
    target = tmp_path / "answer.txt"
    target.write_text("saved")
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    visited = []

    def slow_glob(path, pattern):
        try:
            entered.set()
            release.wait(1)
            for index in range(100):
                visited.append(index)
                yield target
        finally:
            finished.set()

    monkeypatch.setattr(Path, "glob", slow_glob)
    task = asyncio.create_task(
        GlobTool({"working_dir": str(tmp_path)}).execute({"path": str(tmp_path), "pattern": "*.txt"})
    )
    try:
        await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        await asyncio.to_thread(finished.wait, 2)
    assert len(visited) <= 1
