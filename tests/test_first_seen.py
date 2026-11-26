"""first_seen is when the domain was first seen, not when it was last re-resolved:
the 30-day refresh must not reset it."""
import json
import unittest

import resolve
from _fixture import offline_state

STALE = {"org": "example.org", "confidence": "none", "by": "fallback", "resolved_at": 0,
         "first_seen": 5.0, "last_seen": 6.0}


class FirstSeen(unittest.TestCase):
    def test_refresh_keeps_first_seen(self):
        state = offline_state(self, entities={"example.org": STALE})
        self.assertEqual(resolve.main(), 0)
        e = json.loads((state / "entities.json").read_text())["example.org"]
        self.assertGreater(e["resolved_at"], 0, "the stale entity was re-resolved")
        self.assertEqual(e["first_seen"], 5.0)
        self.assertGreater(e["last_seen"], 6.0)


if __name__ == "__main__":
    unittest.main()
