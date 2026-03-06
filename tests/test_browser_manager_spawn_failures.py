import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from browser_manager import BrowserManager, BrowserStartupFailure
from models import BrowserOptions


class _FakeStderr:
    def __init__(self, data: bytes):
        self._buffer = bytearray(data)


class _FakeProcess:
    def __init__(self, *, pid: int, returncode, stderr: bytes):
        self.pid = pid
        self.returncode = returncode
        self.stderr = _FakeStderr(stderr)

    async def wait(self):
        await asyncio.sleep(0.05)
        return self.returncode

    async def communicate(self):
        return b"", bytes(self.stderr._buffer)


class _FakeBrowser:
    def __init__(self, process):
        self._process = process


class BrowserManagerSpawnFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_capture_browser_startup_diagnostics_reads_stderr_buffer(self):
        manager = BrowserManager()
        manager._STARTUP_WAIT_TIMEOUT_SECONDS = 0.01

        browser = _FakeBrowser(
            _FakeProcess(
                pid=4321,
                returncode=None,
                stderr=b"line 1\nOperation not permitted\n",
            )
        )

        diagnostics = await manager._capture_browser_startup_diagnostics(browser)

        self.assertEqual(diagnostics["browser_pid"], 4321)
        self.assertTrue(diagnostics["browser_process_running"])
        self.assertEqual(
            diagnostics["browser_startup_stderr"],
            "line 1\nOperation not permitted",
        )
        self.assertFalse(diagnostics["browser_startup_stderr_truncated"])

    async def test_spawn_browser_failure_records_last_failure_and_stderr(self):
        manager = BrowserManager()
        options = BrowserOptions(headless=True)
        startup_failure = BrowserStartupFailure(
            "Failed to connect to browser",
            diagnostics={
                "browser_pid": 9876,
                "browser_returncode": 1,
                "browser_process_running": False,
                "browser_startup_stderr": "Operation not permitted",
            },
        )

        with patch("browser_manager.get_platform_info", return_value={
            "system": "Darwin",
            "is_root": False,
            "is_container": False,
        }), patch(
            "browser_manager.check_browser_executable",
            return_value="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ), patch(
            "browser_manager.merge_browser_args",
            side_effect=lambda args: args,
        ), patch.object(
            manager,
            "_start_browser_with_timezone",
            AsyncMock(side_effect=startup_failure),
        ), patch(
            "browser_manager.process_cleanup.kill_browser_process"
        ), patch(
            "browser_manager.persistent_storage.remove_instance"
        ):
            with self.assertRaises(Exception) as context:
                await manager.spawn_browser(options)

        message = str(context.exception)
        self.assertIn("Failed to connect to browser", message)
        self.assertIn("Chrome pid: 9876 (exited)", message)
        self.assertIn("Chrome exit code: 1", message)
        self.assertIn("Chrome stderr tail:\nOperation not permitted", message)

        failure_diagnostics = await manager.get_last_spawn_failure_diagnostics()
        self.assertIsNotNone(failure_diagnostics)
        self.assertEqual(failure_diagnostics["failure_stage"], "starting_browser")
        self.assertEqual(failure_diagnostics["browser_pid"], 9876)
        self.assertEqual(
            failure_diagnostics["browser_startup_stderr"],
            "Operation not permitted",
        )


if __name__ == "__main__":
    unittest.main()
