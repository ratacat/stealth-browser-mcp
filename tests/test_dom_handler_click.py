import unittest
from unittest.mock import AsyncMock, patch

import server
from dom_handler import DOMHandler


class _FakeElement:
    def __init__(self, click_point):
        self.click_point = click_point
        self.apply_script = ""
        self.native_fallback_clicked = False

    async def scroll_into_view(self):
        return None

    async def apply(self, script):
        self.apply_script = script
        return self.click_point

    async def click(self):
        self.native_fallback_clicked = True


class _FakeTab:
    def __init__(self, element=None, *, fail_send=False, viewport=None):
        self.element = element
        self.fail_send = fail_send
        self.viewport = viewport or {"width": 1440, "height": 900}
        self.sent = []

    async def select(self, _selector, timeout):
        self.timeout = timeout
        return self.element

    async def evaluate(self, _script, return_by_value=False):
        self.return_by_value = return_by_value
        return self.viewport

    async def send(self, command):
        if self.fail_send:
            raise RuntimeError("CDP send failed")
        self.sent.append(command)


class DOMHandlerClickTests(unittest.IsolatedAsyncioTestCase):
    async def test_click_element_dispatches_requested_offsets_with_humanized_pointer_path(self):
        element = _FakeElement(
            {"x": 130.0, "y": 235.0, "width": 300.0, "height": 70.0, "hit": True}
        )
        tab = _FakeTab(element)
        events = []

        def dispatch(event_type, **kwargs):
            events.append((event_type, kwargs))
            return {"event_type": event_type, **kwargs}

        with (
            patch("nodriver.cdp.input_.dispatch_mouse_event", side_effect=dispatch),
            patch("dom_handler.asyncio.sleep", new=AsyncMock()),
            patch("dom_handler.random.randint", return_value=7),
            patch("dom_handler.random.uniform", return_value=0.01),
        ):
            clicked = await DOMHandler.click_element(
                tab,
                'iframe[src*="challenges.cloudflare.com"]',
                offset_x=30,
                offset_y=35,
                humanize=True,
            )

        self.assertTrue(clicked)
        self.assertIn("const offsetX = 30.0;", element.apply_script)
        self.assertIn("const offsetY = 35.0;", element.apply_script)
        self.assertFalse(element.native_fallback_clicked)
        self.assertEqual([event[0] for event in events].count("mousePressed"), 1)
        self.assertEqual([event[0] for event in events].count("mouseReleased"), 1)
        final_move = [event for event in events if event[0] == "mouseMoved"][-1]
        self.assertAlmostEqual(final_move[1]["x"], 130.0)
        self.assertAlmostEqual(final_move[1]["y"], 235.0)
        pressed = next(event for event in events if event[0] == "mousePressed")
        self.assertEqual((pressed[1]["x"], pressed[1]["y"]), (130.0, 235.0))

    async def test_click_element_keeps_center_click_defaults_when_offsets_are_omitted(self):
        element = _FakeElement(
            {"x": 250.0, "y": 235.0, "width": 300.0, "height": 70.0, "hit": True}
        )
        tab = _FakeTab(element)
        events = []

        def dispatch(event_type, **kwargs):
            events.append((event_type, kwargs))
            return {"event_type": event_type, **kwargs}

        with (
            patch("nodriver.cdp.input_.dispatch_mouse_event", side_effect=dispatch),
            patch("dom_handler.asyncio.sleep", new=AsyncMock()),
        ):
            clicked = await DOMHandler.click_element(tab, "button")

        self.assertTrue(clicked)
        self.assertIn("const offsetX = null;", element.apply_script)
        self.assertIn("const offsetY = null;", element.apply_script)
        self.assertEqual([event[0] for event in events], [
            "mouseMoved",
            "mousePressed",
            "mouseReleased",
        ])
        self.assertFalse(element.native_fallback_clicked)

    async def test_offset_click_does_not_fall_back_to_the_element_center_on_cdp_failure(self):
        element = _FakeElement(
            {"x": 130.0, "y": 235.0, "width": 300.0, "height": 70.0, "hit": True}
        )
        tab = _FakeTab(element, fail_send=True)

        with (
            patch(
                "nodriver.cdp.input_.dispatch_mouse_event",
                return_value={"event_type": "mouseMoved"},
            ),
            patch("dom_handler.asyncio.sleep", new=AsyncMock()),
        ):
            with self.assertRaisesRegex(Exception, "CDP send failed"):
                await DOMHandler.click_element(tab, "iframe", offset_x=30, offset_y=35)

        self.assertFalse(element.native_fallback_clicked)

    async def test_click_coordinates_dispatches_warmup_approach_and_click(self):
        tab = _FakeTab()
        events = []

        def dispatch(event_type, **kwargs):
            events.append((event_type, kwargs))
            return {"event_type": event_type, **kwargs}

        with (
            patch("nodriver.cdp.input_.dispatch_mouse_event", side_effect=dispatch),
            patch("dom_handler.asyncio.sleep", new=AsyncMock()),
            patch("dom_handler.random.randint", side_effect=[3, 7]),
            patch("dom_handler.random.uniform", return_value=0.2),
        ):
            clicked = await DOMHandler.click_coordinates(
                tab, 293, 336, humanize=True, warmup=True
            )

        self.assertTrue(clicked)
        self.assertTrue(tab.return_by_value)
        self.assertEqual([event[0] for event in events].count("mousePressed"), 1)
        self.assertEqual([event[0] for event in events].count("mouseReleased"), 1)
        self.assertGreaterEqual([event[0] for event in events].count("mouseMoved"), 10)
        pressed = next(event for event in events if event[0] == "mousePressed")
        self.assertEqual((pressed[1]["x"], pressed[1]["y"]), (293.0, 336.0))

    async def test_click_coordinates_rejects_points_outside_viewport(self):
        with self.assertRaisesRegex(Exception, "inside the viewport"):
            await DOMHandler.click_coordinates(_FakeTab(), 1600, 336)

class ServerClickToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_click_tool_threads_offsets_and_humanize_to_dom_handler(self):
        tab = object()
        get_tab = AsyncMock(return_value=tab)
        click = AsyncMock(return_value=True)

        with (
            patch.object(server.browser_manager, "get_tab", get_tab),
            patch.object(server.dom_handler, "click_element", click),
        ):
            clicked = await server.click_element.fn(
                "browser-1",
                "iframe",
                timeout=2000,
                offset_x=30,
                offset_y=35,
                humanize=True,
            )

        self.assertTrue(clicked)
        get_tab.assert_awaited_once_with("browser-1")
        click.assert_awaited_once_with(
            tab,
            "iframe",
            None,
            2000,
            offset_x=30,
            offset_y=35,
            humanize=True,
            warmup=False,
        )

    async def test_click_tool_threads_warmup_to_dom_handler(self):
        tab = object()
        get_tab = AsyncMock(return_value=tab)
        click = AsyncMock(return_value=True)

        with (
            patch.object(server.browser_manager, "get_tab", get_tab),
            patch.object(server.dom_handler, "click_element", click),
        ):
            clicked = await server.click_element.fn(
                "browser-1",
                "iframe",
                timeout=2000,
                humanize=True,
                warmup=True,
            )

        self.assertTrue(clicked)
        click.assert_awaited_once_with(
            tab,
            "iframe",
            None,
            2000,
            offset_x=None,
            offset_y=None,
            humanize=True,
            warmup=True,
        )


    async def test_coordinate_click_tool_threads_arguments_to_dom_handler(self):
        tab = object()
        get_tab = AsyncMock(return_value=tab)
        click = AsyncMock(return_value=True)

        with (
            patch.object(server.browser_manager, "get_tab", get_tab),
            patch.object(server.dom_handler, "click_coordinates", click),
        ):
            clicked = await server.click_coordinates.fn(
                "browser-1", 293, 336, humanize=True, warmup=True
            )

        self.assertTrue(clicked)
        get_tab.assert_awaited_once_with("browser-1")
        click.assert_awaited_once_with(
            tab, 293, 336, humanize=True, warmup=True
        )


if __name__ == "__main__":
    unittest.main()
