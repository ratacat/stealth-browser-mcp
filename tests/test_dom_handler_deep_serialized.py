"""Tests for DOMHandler._plain_from_deep_serialized (CDP deep-value normalization)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from dom_handler import DOMHandler


class FakeRemoteObject:
    def __init__(self, value=None, deep_value=None):
        self.value = value
        self.object_id = "obj-1"
        self.deep_serialized_value = (
            type("Deep", (), {"value": deep_value})() if deep_value is not None else None
        )


class TestPlainFromDeepSerialized(unittest.TestCase):
    def plain(self, value):
        return DOMHandler._plain_from_deep_serialized(value)

    def test_primitives_passthrough(self):
        self.assertEqual(self.plain("x"), "x")
        self.assertEqual(self.plain(3), 3)
        self.assertEqual(self.plain(True), True)
        self.assertIsNone(self.plain(None))

    def test_entries_list_becomes_object(self):
        entries = [
            ["detected", {"type": "boolean", "value": True}],
            ["rayId", {"type": "null"}],
            ["count", {"type": "number", "value": 2}],
        ]
        self.assertEqual(
            self.plain(entries),
            {"detected": True, "rayId": None, "count": 2},
        )

    def test_numeric_entries_become_array(self):
        entries = [
            ["0", {"type": "string", "value": "a"}],
            ["1", {"type": "string", "value": "b"}],
        ]
        self.assertEqual(self.plain(entries), ["a", "b"])

    def test_nested_deep_nodes(self):
        node = {
            "type": "object",
            "value": [["items", {"type": "array", "value": [
                {"type": "number", "value": 1},
                {"type": "boolean", "value": False},
            ]}]],
        }
        self.assertEqual(self.plain(node), {"items": [1, False]})

    def test_remote_object_prefers_plain_value(self):
        self.assertEqual(self.plain(FakeRemoteObject(value=False)), False)
        self.assertEqual(self.plain(FakeRemoteObject(value={"a": 1})), {"a": 1})
        self.assertIsNone(self.plain(FakeRemoteObject(value=None)))

    def test_plain_object_with_type_field_preserved(self):
        # App payloads with a non-CDP "type" must not be mistaken for deep nodes.
        payload = {"type": "user", "value": 7, "extra": "kept"}
        self.assertEqual(self.plain(payload), {"type": "user", "value": 7, "extra": "kept"})

    def test_plain_list_not_entries(self):
        self.assertEqual(self.plain([1, 2, {"a": "b"}]), [1, 2, {"a": "b"}])


if __name__ == "__main__":
    unittest.main()
