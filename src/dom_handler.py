"""DOM manipulation and element interaction utilities."""

import asyncio
import json
import math
import random
import time
from typing import List, Optional, Dict, Any

from nodriver import Tab, Element
from models import ElementInfo, ElementAction
from debug_logger import debug_logger



class DOMHandler:
    """Handles DOM queries and element interactions."""

    @staticmethod
    async def query_elements(
        tab: Tab,
        selector: str,
        text_filter: Optional[str] = None,
        visible_only: bool = True,
        limit: Optional[Any] = None
    ) -> List[ElementInfo]:
        """
        Query elements with advanced filtering.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS or XPath selector for elements.
            text_filter (Optional[str]): Filter elements by text content.
            visible_only (bool): Only include visible elements.
            limit (Optional[Any]): Limit the number of results.

        Returns:
            List[ElementInfo]: List of element information objects.
        """
        processed_limit = None
        if limit is not None:
            try:
                if isinstance(limit, int):
                    processed_limit = limit
                elif isinstance(limit, str) and limit.isdigit():
                    processed_limit = int(limit)
                elif isinstance(limit, str) and limit.strip() == '':
                    processed_limit = None
                else:
                    debug_logger.log_warning('DOMHandler', 'query_elements',
                                            f'Invalid limit parameter: {limit} (type: {type(limit)})')
                    processed_limit = None
            except (ValueError, TypeError) as e:
                debug_logger.log_error('DOMHandler', 'query_elements', e,
                                      {'limit_value': limit, 'limit_type': type(limit)})
                processed_limit = None

        debug_logger.log_info('DOMHandler', 'query_elements',
                             f'Starting query with selector: {selector}',
                             {'text_filter': text_filter, 'visible_only': visible_only,
                              'limit': limit, 'processed_limit': processed_limit})
        try:
            if selector.startswith('//'):
                elements = await tab.xpath(selector)
                debug_logger.log_info('DOMHandler', 'query_elements',
                                     f'XPath query returned {len(elements)} elements')
            else:
                elements = await tab.select_all(selector)
                debug_logger.log_info('DOMHandler', 'query_elements',
                                     f'CSS query returned {len(elements)} elements')

            results = []
            for idx, elem in enumerate(elements):
                try:
                    if hasattr(elem, 'update'):
                        await elem.update()

                    tag_name = elem.tag_name if hasattr(elem, 'tag_name') else 'unknown'
                    text_content = elem.text_all if hasattr(elem, 'text_all') else ''
                    attrs = elem.attrs if hasattr(elem, 'attrs') else {}

                    if text_filter and text_filter.lower() not in text_content.lower():
                        continue

                    is_visible = True
                    if visible_only:
                        try:
                            is_visible = await elem.apply(
                                """(elem) => {
                                    var style = window.getComputedStyle(elem);
                                    return style.display !== 'none' && 
                                           style.visibility !== 'hidden' && 
                                           style.opacity !== '0';
                                }"""
                            )
                            if not is_visible:
                                continue
                        except:
                            pass

                    bbox = None
                    try:
                        position = await elem.get_position()
                        if position:
                            bbox = {
                                'x': position.x,
                                'y': position.y,
                                'width': position.width,
                                'height': position.height
                            }
                    except Exception:
                        pass

                    is_clickable = False

                    children_count = 0
                    try:
                        if hasattr(elem, 'children'):
                            children = elem.children
                            children_count = len(children) if children else 0
                    except Exception:
                        pass

                    element_info = ElementInfo(
                        selector=selector,
                        tag_name=tag_name,
                        text=text_content[:500] if text_content else None,
                        attributes=attrs or {},
                        is_visible=is_visible,
                        is_clickable=is_clickable,
                        bounding_box=bbox,
                        children_count=children_count
                    )

                    results.append(element_info)

                    if processed_limit and len(results) >= processed_limit:
                        debug_logger.log_info('DOMHandler', 'query_elements',
                                             f'Reached limit of {processed_limit} results')
                        break

                except Exception as elem_error:
                    debug_logger.log_error('DOMHandler', 'query_elements',
                                          elem_error,
                                          {'element_index': idx, 'selector': selector})
                    continue

            debug_logger.log_info('DOMHandler', 'query_elements',
                                 f'Returning {len(results)} results')
            return results

        except Exception as e:
            debug_logger.log_error('DOMHandler', 'query_elements', e,
                                  {'selector': selector, 'tab': str(tab)})
            return []

    @staticmethod
    async def click_coordinates(
        tab: Tab,
        x: float,
        y: float,
        humanize: bool = False,
        warmup: bool = False
    ) -> bool:
        """Click a viewport coordinate with trusted CDP pointer events."""
        try:
            from nodriver import cdp

            x_value = float(x)
            y_value = float(y)
            if not math.isfinite(x_value) or not math.isfinite(y_value):
                raise ValueError("coordinates must be finite")
            if x_value < 0 or y_value < 0:
                raise ValueError("coordinates must be non-negative")

            viewport = await tab.evaluate(
                "({ width: window.innerWidth, height: window.innerHeight })",
                return_by_value=True,
            )
            viewport = DOMHandler._plain_from_deep_serialized(viewport)
            viewport_width = float((viewport or {}).get("width") or 1280)
            viewport_height = float((viewport or {}).get("height") or 720)
            if x_value >= viewport_width or y_value >= viewport_height:
                raise ValueError("coordinates must be inside the viewport")

            if warmup:
                humanize = True
                for _ in range(random.randint(3, 6)):
                    await tab.send(cdp.input_.dispatch_mouse_event(
                        "mouseMoved",
                        x=random.uniform(0.15, 0.85) * viewport_width,
                        y=random.uniform(0.15, 0.8) * viewport_height,
                        button=cdp.input_.MouseButton("none"),
                        buttons=0,
                    ))
                    await asyncio.sleep(random.uniform(0.03, 0.09))

            if humanize:
                start_x = min(max(x_value + random.uniform(-80, 80), 0), viewport_width - 1)
                start_y = min(max(y_value + random.uniform(-45, 45), 0), viewport_height - 1)
                control_x = (start_x + x_value) / 2 + random.uniform(-25, 25)
                control_y = (start_y + y_value) / 2 + random.uniform(-18, 18)
                steps = random.randint(7, 12)
                for step in range(1, steps + 1):
                    progress = step / steps
                    inverse = 1 - progress
                    await tab.send(cdp.input_.dispatch_mouse_event(
                        "mouseMoved",
                        x=(inverse * inverse * start_x + 2 * inverse * progress * control_x + progress * progress * x_value),
                        y=(inverse * inverse * start_y + 2 * inverse * progress * control_y + progress * progress * y_value),
                        button=cdp.input_.MouseButton("none"),
                        buttons=0,
                    ))
                    await asyncio.sleep(random.uniform(0.008, 0.02))
                await asyncio.sleep(random.uniform(0.15, 0.45))
            else:
                await tab.send(cdp.input_.dispatch_mouse_event(
                    "mouseMoved", x=x_value, y=y_value,
                    button=cdp.input_.MouseButton("none"), buttons=0,
                ))
                await asyncio.sleep(0.08)

            await tab.send(cdp.input_.dispatch_mouse_event(
                "mousePressed", x=x_value, y=y_value,
                button=cdp.input_.MouseButton("left"), buttons=1, click_count=1,
            ))
            await asyncio.sleep(random.uniform(0.06, 0.16) if humanize else 0.06)
            await tab.send(cdp.input_.dispatch_mouse_event(
                "mouseReleased", x=x_value, y=y_value,
                button=cdp.input_.MouseButton("left"), buttons=0, click_count=1,
            ))
            return True
        except Exception as e:
            raise Exception(f"Failed to click coordinates: {str(e)}")

    @staticmethod
    async def click_element(
        tab: Tab,
        selector: str,
        text_match: Optional[str] = None,
        timeout: int = 10000,
        offset_x: Optional[float] = None,
        offset_y: Optional[float] = None,
        humanize: bool = False,
        warmup: bool = False
    ) -> bool:
        """
        Click an element with smart retry logic.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the element.
            text_match (Optional[str]): Match element by text content.
            timeout (int): Timeout in milliseconds.
            offset_x (Optional[float]): Horizontal click offset from the element's left edge.
            offset_y (Optional[float]): Vertical click offset from the element's top edge.
            humanize (bool): Move the pointer along a paced curved path before clicking.
            warmup (bool): Emit a few wandering pointer moves across the viewport
                before the approach path, so behavioral monitors (e.g. Cloudflare
                Turnstile) observe a movement history instead of a click from
                nowhere. Implies humanize.

        Returns:
            bool: True if click succeeded, False otherwise.
        """
        try:
            offset_x_value = None if offset_x is None else float(offset_x)
            offset_y_value = None if offset_y is None else float(offset_y)
            if offset_x_value is not None and not math.isfinite(offset_x_value):
                raise ValueError("offset_x must be finite")
            if offset_y_value is not None and not math.isfinite(offset_y_value):
                raise ValueError("offset_y must be finite")

            element = None

            if text_match:
                element = await tab.find(text_match, best_match=True)
            else:
                element = await tab.select(selector, timeout=timeout/1000)

            if not element:
                raise Exception(f"Element not found: {selector}")

            await element.scroll_into_view()
            await asyncio.sleep(0.5)

            try:
                from nodriver import cdp

                click_point = await element.apply(
                    """(elem) => {
                        const offsetX = %s;
                        const offsetY = %s;
                        const rect = elem.getBoundingClientRect();
                        if (!rect || rect.width < 1 || rect.height < 1) {
                            return null;
                        }
                        const clampOffset = (offset, size) =>
                            offset === null
                                ? size / 2
                                : Math.min(Math.max(offset, 1), Math.max(size - 1, 1));
                        const x = rect.left + clampOffset(offsetX, rect.width);
                        const y = rect.top + clampOffset(offsetY, rect.height);
                        const top = document.elementFromPoint(x, y);
                        const hit = top === elem || elem.contains(top);
                        return { x, y, width: rect.width, height: rect.height, hit,
                                 vw: window.innerWidth, vh: window.innerHeight };
                    }""" % (json.dumps(offset_x_value), json.dumps(offset_y_value))
                )
                if not click_point:
                    raise Exception("Element click point not available")
                if isinstance(click_point, str):
                    click_point = json.loads(click_point)
                if not click_point.get("hit", False):
                    raise Exception("Element click point is covered")
                x = float(click_point["x"])
                y = float(click_point["y"])

                if warmup:
                    humanize = True
                    vw = float(click_point.get("vw") or 1280)
                    vh = float(click_point.get("vh") or 720)
                    wander_count = random.randint(3, 6)
                    for _ in range(wander_count):
                        wander_x = min(max(random.uniform(0.15, 0.85) * vw, 0), vw - 1)
                        wander_y = min(max(random.uniform(0.15, 0.8) * vh, 0), vh - 1)
                        await tab.send(cdp.input_.dispatch_mouse_event(
                            "mouseMoved",
                            x=wander_x,
                            y=wander_y,
                            button=cdp.input_.MouseButton("none"),
                            buttons=0,
                        ))
                        await asyncio.sleep(random.uniform(0.03, 0.09))

                if humanize:
                    start_x = max(0, x + random.uniform(-80, 80))
                    start_y = max(0, y + random.uniform(-45, 45))
                    control_x = (start_x + x) / 2 + random.uniform(-25, 25)
                    control_y = (start_y + y) / 2 + random.uniform(-18, 18)
                    steps = random.randint(7, 12)
                    for step in range(1, steps + 1):
                        progress = step / steps
                        inverse = 1 - progress
                        move_x = (
                            inverse * inverse * start_x
                            + 2 * inverse * progress * control_x
                            + progress * progress * x
                        )
                        move_y = (
                            inverse * inverse * start_y
                            + 2 * inverse * progress * control_y
                            + progress * progress * y
                        )
                        await tab.send(cdp.input_.dispatch_mouse_event(
                            "mouseMoved",
                            x=move_x,
                            y=move_y,
                            button=cdp.input_.MouseButton("none"),
                            buttons=0,
                        ))
                        await asyncio.sleep(random.uniform(0.008, 0.02))
                else:
                    await tab.send(cdp.input_.dispatch_mouse_event(
                        "mouseMoved",
                        x=x,
                        y=y,
                        button=cdp.input_.MouseButton("none"),
                        buttons=0,
                    ))
                    await asyncio.sleep(0.08)

                if humanize:
                    # Hover on the target briefly before pressing.
                    await asyncio.sleep(random.uniform(0.15, 0.45))
                await tab.send(cdp.input_.dispatch_mouse_event(
                    "mousePressed",
                    x=x,
                    y=y,
                    button=cdp.input_.MouseButton("left"),
                    buttons=1,
                    click_count=1,
                ))
                if humanize:
                    # Human press-hold before release.
                    await asyncio.sleep(random.uniform(0.06, 0.16))
                else:
                    await asyncio.sleep(0.06)
                await tab.send(cdp.input_.dispatch_mouse_event(
                    "mouseReleased",
                    x=x,
                    y=y,
                    button=cdp.input_.MouseButton("left"),
                    buttons=0,
                    click_count=1,
                ))
            except Exception:
                if offset_x_value is not None or offset_y_value is not None:
                    raise
                await element.click()

            return True

        except Exception as e:
            raise Exception(f"Failed to click element: {str(e)}")

    @staticmethod
    async def type_text(
        tab: Tab,
        selector: str,
        text: str,
        clear_first: bool = True,
        delay_ms: int = 50,
        parse_newlines: bool = False,
        shift_enter: bool = False
    ) -> bool:
        """
        Type text with human-like delays and optional newline parsing.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the input element.
            text (str): Text to type.
            clear_first (bool): Clear input before typing.
            delay_ms (int): Delay between keystrokes in milliseconds.
            parse_newlines (bool): If True, parse \n as Enter key presses.
            shift_enter (bool): If True, use Shift+Enter instead of Enter (for chat apps).

        Returns:
            bool: True if typing succeeded, False otherwise.
        """
        from nodriver import cdp

        try:
            element = await tab.select(selector)
            if not element:
                raise Exception(f"Element not found: {selector}")

            await element.focus()
            await asyncio.sleep(0.1)

            if clear_first:
                try:
                    await element.apply("(elem) => { elem.value = ''; }")
                except:
                    await element.send_keys('\ue009' + 'a')
                    await element.send_keys('\ue017')
                await asyncio.sleep(0.1)

            if parse_newlines:
                from nodriver import cdp
                lines = text.split('\n')
                for i, line in enumerate(lines):
                    for char in line:
                        await tab.send(cdp.input_.dispatch_key_event("char", text=char))
                        await asyncio.sleep(delay_ms / 1000)
                    
                    if i < len(lines) - 1:
                        if shift_enter:
                            await element.apply('''(elem) => {
                                const start = elem.selectionStart;
                                const end = elem.selectionEnd;
                                const value = elem.value;
                                elem.value = value.substring(0, start) + '\\n' + value.substring(end);
                                elem.selectionStart = elem.selectionEnd = start + 1;
                                
                                elem.dispatchEvent(new KeyboardEvent('keydown', {
                                    key: 'Enter',
                                    code: 'Enter',
                                    shiftKey: true,
                                    bubbles: true
                                }));
                                elem.dispatchEvent(new Event('input', { bubbles: true }));
                            }''')
                        else:
                            await element.apply('''(elem) => {
                                const start = elem.selectionStart;
                                const end = elem.selectionEnd;
                                const value = elem.value;
                                elem.value = value.substring(0, start) + '\\n' + value.substring(end);
                                elem.selectionStart = elem.selectionEnd = start + 1;
                                
                                elem.dispatchEvent(new KeyboardEvent('keydown', {
                                    key: 'Enter',
                                    code: 'Enter',
                                    bubbles: true
                                }));
                                elem.dispatchEvent(new Event('input', { bubbles: true }));
                            }''')
                        await asyncio.sleep(delay_ms / 1000)
            else:
                for char in text:
                    await tab.send(cdp.input_.dispatch_key_event("char", text=char))
                    await asyncio.sleep(delay_ms / 1000)

            return True

        except Exception as e:
            raise Exception(f"Failed to type text: {str(e)}")

    @staticmethod
    async def press_key(
        tab: Tab,
        key: str,
        selector: Optional[str] = None,
        delay_ms: int = 50,
        modifiers: int = 0
    ) -> bool:
        """
        Press a keyboard key using Chrome DevTools input events.

        Args:
            tab (Tab): The browser tab object.
            key (str): Key name to press.
            selector (Optional[str]): CSS selector to focus before pressing.
            delay_ms (int): Delay between key down and key up in milliseconds.
            modifiers (int): CDP modifier bit field.

        Returns:
            bool: True if the key press succeeded, False otherwise.
        """
        from nodriver import cdp

        key_map = {
            "Enter": ("Enter", "Enter", 13),
            "Tab": ("Tab", "Tab", 9),
            "Escape": ("Escape", "Escape", 27),
            "Backspace": ("Backspace", "Backspace", 8),
            "Delete": ("Delete", "Delete", 46),
        }

        try:
            if selector:
                element = await tab.select(selector)
                if not element:
                    raise Exception(f"Element not found: {selector}")
                await element.focus()
                await asyncio.sleep(0.08)

            key_name, code, virtual_key_code = key_map.get(key, (key, key, 0))
            await tab.send(cdp.input_.dispatch_key_event(
                "rawKeyDown",
                modifiers=modifiers,
                key=key_name,
                code=code,
                windows_virtual_key_code=virtual_key_code,
            ))
            await asyncio.sleep(delay_ms / 1000)
            await tab.send(cdp.input_.dispatch_key_event(
                "keyUp",
                modifiers=modifiers,
                key=key_name,
                code=code,
                windows_virtual_key_code=virtual_key_code,
            ))
            return True

        except Exception as e:
            raise Exception(f"Failed to press key: {str(e)}")

    @staticmethod
    async def paste_text(
        tab: Tab,
        selector: str,
        text: str,
        clear_first: bool = True
    ) -> bool:
        """
        Paste text instantly using nodriver's insert_text method.
        This is much faster than typing character by character.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the input element.
            text (str): Text to paste.
            clear_first (bool): Clear input before pasting.

        Returns:
            bool: True if pasting succeeded, False otherwise.
        """
        from nodriver import cdp
        
        try:
            element = await tab.select(selector)
            if not element:
                raise Exception(f"Element not found: {selector}")

            await element.focus()
            await asyncio.sleep(0.1)

            if clear_first:
                try:
                    await element.apply("(elem) => { elem.value = ''; }")
                except:
                    await tab.send(cdp.input_.dispatch_key_event(
                        "rawKeyDown", 
                        modifiers=2,  # Ctrl
                        key="a",
                        code="KeyA",
                        windows_virtual_key_code=65
                    ))
                    await tab.send(cdp.input_.dispatch_key_event(
                        "keyUp", 
                        modifiers=2,  # Ctrl
                        key="a",
                        code="KeyA",
                        windows_virtual_key_code=65
                    ))
                    await tab.send(cdp.input_.dispatch_key_event(
                        "rawKeyDown",
                        key="Delete",
                        code="Delete",
                        windows_virtual_key_code=46
                    ))
                    await tab.send(cdp.input_.dispatch_key_event(
                        "keyUp",
                        key="Delete", 
                        code="Delete",
                        windows_virtual_key_code=46
                    ))
                await asyncio.sleep(0.1)

            await tab.send(cdp.input_.insert_text(text))

            return True

        except Exception as e:
            raise Exception(f"Failed to paste text: {str(e)}")

    @staticmethod
    async def select_option(
        tab: Tab,
        selector: str,
        value: Optional[str] = None,
        text: Optional[str] = None,
        index: Optional[int] = None
    ) -> bool:
        """
        Select option from dropdown using nodriver's native methods.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the select element.
            value (Optional[str]): Option value to select.
            text (Optional[str]): Option text to select.
            index (Optional[int]): Option index to select.

        Returns:
            bool: True if option selected, False otherwise.
        """
        try:
            select_element = await tab.select(selector)
            if not select_element:
                raise Exception(f"Select element not found: {selector}")

            if text is not None:
                await select_element.send_keys(text)
                return True

            if value is not None:
                safe_selector = json.dumps(selector)
                safe_value = json.dumps(value)
                await tab.evaluate(f"""
                    const select = document.querySelector({safe_selector});
                    if (select) {{
                        select.value = {safe_value};
                        select.dispatchEvent(new Event('change', {{bubbles: true}}));
                    }}
                """)
                return True

            elif index is not None:
                safe_selector = json.dumps(selector)
                safe_index = int(index)
                await tab.evaluate(f"""
                    const select = document.querySelector({safe_selector});
                    if (select && {safe_index} >= 0 && {safe_index} < select.options.length) {{
                        select.selectedIndex = {safe_index};
                        select.dispatchEvent(new Event('change', {{bubbles: true}}));
                    }}
                """)
                return True

            raise Exception("No selection criteria provided (value, text, or index)")

        except Exception as e:
            raise Exception(f"Failed to select option: {str(e)}")

    @staticmethod
    async def get_element_state(
        tab: Tab,
        selector: str
    ) -> Dict[str, Any]:
        """
        Get complete state of an element.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the element.

        Returns:
            Dict[str, Any]: Dictionary of element state properties.
        """
        try:
            element = await tab.select(selector)
            if not element:
                raise Exception(f"Element not found: {selector}")

            if hasattr(element, 'update'):
                await element.update()

            state = {
                'tag_name': element.tag_name if hasattr(element, 'tag_name') else 'unknown',
                'text': element.text if hasattr(element, 'text') else '',
                'text_all': element.text_all if hasattr(element, 'text_all') else '',
                'attributes': element.attrs if hasattr(element, 'attrs') else {},
                'is_visible': True,
                'is_clickable': False,
                'is_enabled': True,
                'value': element.attrs.get('value') if hasattr(element, 'attrs') else None,
                'href': element.attrs.get('href') if hasattr(element, 'attrs') else None,
                'src': element.attrs.get('src') if hasattr(element, 'attrs') else None,
                'class': element.attrs.get('class') if hasattr(element, 'attrs') else None,
                'id': element.attrs.get('id') if hasattr(element, 'attrs') else None,
                'position': await element.get_position() if hasattr(element, 'get_position') else None,
                'computed_style': {},
                'children_count': len(element.children) if hasattr(element, 'children') and element.children else 0,
                'parent_tag': None
            }

            return state

        except Exception as e:
            raise Exception(f"Failed to get element state: {str(e)}")

    @staticmethod
    async def wait_for_element(
        tab: Tab,
        selector: str,
        timeout: int = 30000,
        visible: bool = True,
        text_content: Optional[str] = None
    ) -> bool:
        """
        Wait for element to appear and match conditions.

        Args:
            tab (Tab): The browser tab object.
            selector (str): CSS selector for the element.
            timeout (int): Timeout in milliseconds.
            visible (bool): Wait for element to be visible.
            text_content (Optional[str]): Wait for element to contain text.

        Returns:
            bool: True if element matches conditions, False otherwise.
        """
        start_time = time.time()
        timeout_seconds = timeout / 1000

        while time.time() - start_time < timeout_seconds:
            try:
                element = await tab.select(selector)

                if element:
                    if visible:
                        try:
                            is_visible = await element.apply(
                                """(elem) => {
                                    var style = window.getComputedStyle(elem);
                                    return style.display !== 'none' && 
                                           style.visibility !== 'hidden' && 
                                           style.opacity !== '0';
                                }"""
                            )
                            if not is_visible:
                                await asyncio.sleep(0.5)
                                continue
                        except:
                            pass

                    if text_content:
                        text = element.text_all
                        if text_content not in text:
                            await asyncio.sleep(0.5)
                            continue

                    return True

            except Exception:
                pass

            await asyncio.sleep(0.5)

        return False

    @staticmethod
    def _plain_from_deep_serialized(value: Any) -> Any:
        """Normalize CDP deep-serialized values (and RemoteObjects) to plain JSON.

        nodriver's evaluate() returns deep-serialized shapes for objects
        (entry lists of [key, {type, value}]) and RemoteObjects for falsy
        primitives. Chrome's returnByValue path already yields plain JSON, so
        this runs as a safe normalization over whatever came back.
        """
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        # nodriver RemoteObject: prefer plain .value, then deep payload.
        if hasattr(value, "deep_serialized_value") or hasattr(value, "object_id"):
            plain = getattr(value, "value", None)
            if plain is not None:
                return DOMHandler._plain_from_deep_serialized(plain)
            deep = getattr(value, "deep_serialized_value", None)
            if deep is not None:
                return DOMHandler._plain_from_deep_serialized(
                    getattr(deep, "value", None)
                )
            return None
        if isinstance(value, dict):
            # A single deep-serialized node: {"type": <cdp-type>, "value": ...}
            node_type = value.get("type")
            if (
                isinstance(node_type, str)
                and node_type
                in {
                    "string", "number", "boolean", "bigint", "object",
                    "array", "null", "undefined", "regexp", "date",
                    "map", "set", "error",
                }
                and ("value" in value or node_type in ("null", "undefined"))
                and len(value) <= 4
            ):
                if node_type in ("null", "undefined"):
                    return None
                inner = value.get("value")
                if node_type == "object" and isinstance(inner, list):
                    return DOMHandler._entries_to_plain(inner)
                if node_type == "array" and isinstance(inner, list):
                    return [
                        DOMHandler._plain_from_deep_serialized(item)
                        for item in inner
                    ]
                return DOMHandler._plain_from_deep_serialized(inner)
            return {
                key: DOMHandler._plain_from_deep_serialized(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            # Entry-list shape for a deep-serialized object: [[key, node], ...]
            if value and all(
                isinstance(entry, (list, tuple))
                and len(entry) == 2
                and isinstance(entry[0], str)
                and isinstance(entry[1], dict)
                and "type" in entry[1]
                for entry in value
            ):
                return DOMHandler._entries_to_plain(value)
            return [DOMHandler._plain_from_deep_serialized(item) for item in value]
        return value

    @staticmethod
    def _entries_to_plain(entries: List[Any]) -> Any:
        result: Dict[str, Any] = {}
        all_numeric = len(entries) > 0
        for entry in entries:
            key, node = entry
            if not key.isdigit():
                all_numeric = False
            result[key] = DOMHandler._plain_from_deep_serialized(node)
        if all_numeric:
            return [result[str(i)] for i in range(len(result))]
        return result

    @staticmethod
    async def execute_script(
        tab: Tab,
        script: str,
        args: Optional[List[Any]] = None
    ) -> Any:
        """
        Execute JavaScript in page context.

        Args:
            tab (Tab): The browser tab object.
            script (str): JavaScript code to execute.
            args (Optional[List[Any]]): Arguments for the script.

        Returns:
            Any: Result of script execution, normalized to plain JSON.
        """
        try:
            if args:
                serialized_args = ",".join(json.dumps(a) for a in args)
                result = await tab.evaluate(
                    f'(function() {{ {script} }})({serialized_args})',
                    return_by_value=True,
                )
            else:
                result = await tab.evaluate(script, return_by_value=True)

            return DOMHandler._plain_from_deep_serialized(result)

        except Exception as e:
            raise Exception(f"Failed to execute script: {str(e)}")

    @staticmethod
    async def get_page_content(
        tab: Tab,
        include_frames: bool = False
    ) -> Dict[str, str]:
        """
        Get page HTML and text content.

        Args:
            tab (Tab): The browser tab object.
            include_frames (bool): Include iframe contents.

        Returns:
            Dict[str, str]: Dictionary with page content.
        """
        try:
            html = await tab.get_content()
            text = await tab.evaluate("document.body.innerText")

            content = {
                'html': html,
                'text': text,
                'url': await tab.evaluate("window.location.href"),
                'title': await tab.evaluate("document.title")
            }

            if include_frames:
                frames = []
                iframe_elements = await tab.select_all('iframe')

                for i, iframe in enumerate(iframe_elements):
                    try:
                        src = iframe.attrs.get('src') if hasattr(iframe, 'attrs') else None
                        if src:
                            frames.append({
                                'index': i,
                                'src': src,
                                'id': iframe.attrs.get('id') if hasattr(iframe, 'attrs') else None,
                                'name': iframe.attrs.get('name') if hasattr(iframe, 'attrs') else None
                            })
                    except Exception:
                        continue

                content['frames'] = frames

            return content

        except Exception as e:
            raise Exception(f"Failed to get page content: {str(e)}")

    @staticmethod
    async def scroll_page(
        tab: Tab,
        direction: str = "down",
        amount: int = 500,
        smooth: bool = True
    ) -> bool:
        """
        Scroll the page in specified direction.

        Args:
            tab (Tab): The browser tab object.
            direction (str): Direction to scroll ('down', 'up', 'right', 'left', 'top', 'bottom').
            amount (int): Amount to scroll in pixels.
            smooth (bool): Use smooth scrolling.

        Returns:
            bool: True if scroll succeeded, False otherwise.
        """
        try:
            behavior = "'smooth'" if smooth else "'instant'"

            if direction == "down":
                script = f"window.scrollBy({{top: {amount}, left: 0, behavior: {behavior}}})"
            elif direction == "up":
                script = f"window.scrollBy({{top: -{amount}, left: 0, behavior: {behavior}}})"
            elif direction == "right":
                script = f"window.scrollBy({{top: 0, left: {amount}, behavior: {behavior}}})"
            elif direction == "left":
                script = f"window.scrollBy({{top: 0, left: -{amount}, behavior: {behavior}}})"
            elif direction == "top":
                script = f"window.scrollTo({{top: 0, left: 0, behavior: {behavior}}})"
            elif direction == "bottom":
                script = f"window.scrollTo({{top: document.body.scrollHeight, left: 0, behavior: {behavior}}})"
            else:
                raise ValueError(f"Invalid scroll direction: {direction}")

            await tab.evaluate(script)
            await asyncio.sleep(0.5 if smooth else 0.1)

            return True

        except Exception as e:
            raise Exception(f"Failed to scroll page: {str(e)}")
