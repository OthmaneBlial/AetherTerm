"""Untrusted frames and bounded connection bookkeeping."""

import base64
import json
import unittest
import uuid

from server.limits import MAX_FRAME_BYTES, SlidingWindowLimiter
from server.protocol import ProtocolError, parse_message


class ProtocolTests(unittest.TestCase):
    def test_rejects_unknown_incomplete_and_non_object_messages(self):
        for raw in ('{', '[]', '{}', '{"type":[]}', '{"type":"term_input"}',
                    '{"type":"resize","sessionId":"bad","rows":24,"cols":80}'):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                parse_message(raw, "browser")

    def test_rejects_large_and_invalid_terminal_frames(self):
        session_id = str(uuid.uuid4())
        bad_frames = [
            {"type": "term_input", "sessionId": session_id, "input": "@@@"},
            {"type": "term_input", "sessionId": session_id, "input": base64.b64encode(b"x" * 16385).decode()},
            {"type": "resize", "sessionId": session_id, "cols": True, "rows": 24},
            {"type": "resize", "sessionId": session_id, "cols": 501, "rows": 24},
            {"type": "resize", "sessionId": session_id, "cols": 80, "rows": 1},
        ]
        for frame in bad_frames:
            with self.subTest(frame=frame["type"]), self.assertRaises(ProtocolError):
                parse_message(json.dumps(frame), "browser")
        with self.assertRaises(ProtocolError):
            parse_message(" " * (MAX_FRAME_BYTES + 1), "agent")
        self.assertEqual(parse_message(json.dumps({"type": "term_input", "sessionId": session_id,
                                                  "input": base64.b64encode(b"ok").decode()}), "browser")["type"], "term_input")

    def test_limiter_bounds_addresses_and_events(self):
        limiter = SlidingWindowLimiter(2, 60, max_keys=3)
        self.assertTrue(limiter.allow("same"))
        self.assertTrue(limiter.allow("same"))
        self.assertFalse(limiter.allow("same"))
        for address in ("a", "b", "c", "d"):
            self.assertTrue(limiter.allow(address))
        self.assertLessEqual(len(limiter.events), 3)
        self.assertTrue(all(len(events) <= 2 for events in limiter.events.values()))
