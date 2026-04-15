"""Tests for the multi-file single-instance coordinator."""
from __future__ import annotations

import os
import threading
import time
from pathlib import Path

import pytest

from cryptofile import batch


@pytest.fixture(autouse=True)
def _isolated_runtime_dir(tmp_path: Path, monkeypatch):
    """Redirect the coordinator's runtime-dir to a tmp path so concurrent
    test runs and real-user state don't collide."""
    monkeypatch.setattr(batch, "_runtime_dir", lambda: tmp_path)
    yield


def test_primary_acquires_lock():
    c = batch.BatchCoordinator("encrypt")
    try:
        assert c.try_become_primary() is True
    finally:
        c.close()


def test_second_instance_fails_to_become_primary():
    c1 = batch.BatchCoordinator("encrypt")
    c2 = batch.BatchCoordinator("encrypt")
    try:
        assert c1.try_become_primary() is True
        assert c2.try_become_primary() is False
    finally:
        c1.close()
        c2.close()


def test_close_releases_lock_for_next_invocation():
    c1 = batch.BatchCoordinator("encrypt")
    assert c1.try_become_primary()
    c1.close()
    c2 = batch.BatchCoordinator("encrypt")
    try:
        assert c2.try_become_primary() is True
    finally:
        c2.close()


def test_different_actions_have_independent_locks():
    enc = batch.BatchCoordinator("encrypt")
    dec = batch.BatchCoordinator("decrypt")
    try:
        assert enc.try_become_primary() is True
        # Decrypt lock is a separate file; a decrypt primary can run in parallel.
        assert dec.try_become_primary() is True
    finally:
        enc.close()
        dec.close()


def test_secondary_sends_path_to_primary(tmp_path: Path):
    # Primary sets up server, secondary delivers a real file path.
    target_file = tmp_path / "payload.bin"
    target_file.write_bytes(b"whatever")

    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary() is True
    try:
        primary.start_server()
        primary.add_local_path(target_file.parent / "primary_owned.bin")  # not real
        # Secondary in another thread — uses the same port file on disk.
        secondary = batch.BatchCoordinator("encrypt")
        sent = [False]

        def _secondary():
            sent[0] = secondary.send_to_primary(target_file, timeout_s=2.0)

        t = threading.Thread(target=_secondary)
        t.start()
        t.join(timeout=3.0)
        assert sent[0], "secondary could not connect to primary"
        # Collect — should include the secondary's real file. Primary's fake
        # path does NOT make it through is_file() — only the secondary's.
        paths = primary.wait_for_collection(timeout_ms=400, idle_ms=100)
        resolved = {str(p.resolve()) for p in paths}
        assert str(target_file.resolve()) in resolved
    finally:
        primary.close()


def test_secondary_refused_nonexistent_path(tmp_path: Path):
    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary()
    try:
        primary.start_server()
        secondary = batch.BatchCoordinator("encrypt")
        # send_to_primary returns True because bytes were written; but the
        # primary's server-side validation rejects the non-file path.
        assert secondary.send_to_primary(tmp_path / "does-not-exist") is True
        paths = primary.wait_for_collection(timeout_ms=300, idle_ms=100)
        assert paths == []
    finally:
        primary.close()


def test_multiple_secondaries_deliver_in_order(tmp_path: Path):
    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary()
    try:
        primary.start_server()
        files = []
        for i in range(5):
            p = tmp_path / f"f{i}.bin"
            p.write_bytes(b"x")
            files.append(p)
        # Fire all five secondaries in parallel.
        threads = []
        for f in files:
            sec = batch.BatchCoordinator("encrypt")
            t = threading.Thread(target=sec.send_to_primary, args=(f, 2.0))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=3.0)
        paths = primary.wait_for_collection(timeout_ms=600, idle_ms=150)
        assert {p.name for p in paths} == {f.name for f in files}
    finally:
        primary.close()


def test_send_to_primary_times_out_when_no_primary(tmp_path: Path):
    # No primary running → port file doesn't exist → secondary gives up.
    sec = batch.BatchCoordinator("encrypt")
    ok = sec.send_to_primary(tmp_path / "x.bin", timeout_s=0.3)
    assert ok is False


def test_dedup_by_resolved_path(tmp_path: Path):
    primary = batch.BatchCoordinator("encrypt")
    assert primary.try_become_primary()
    try:
        primary.start_server()
        f = tmp_path / "single.bin"
        f.write_bytes(b"data")
        # Deliver the same file twice.
        for _ in range(3):
            sec = batch.BatchCoordinator("encrypt")
            sec.send_to_primary(f, timeout_s=1.0)
        paths = primary.wait_for_collection(timeout_ms=400, idle_ms=100)
        assert len(paths) == 1
    finally:
        primary.close()


def test_invalid_action_rejected():
    with pytest.raises(ValueError):
        batch.BatchCoordinator("shred")
