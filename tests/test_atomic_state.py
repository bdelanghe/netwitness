"""A run interrupted while writing its state (launchd's SIGTERM at logout, a full disk)
must leave the previous state readable. A truncated entities.json or cursor made
every later run die on the parse, for good."""
import json
import unittest
from pathlib import Path
from unittest import mock

import resolve
from _fixture import offline_state

ENTITY = {"org": "Example Org", "confidence": "high", "by": "cert", "resolved_at": 99999999999}


class AtomicState(unittest.TestCase):
    def test_interrupted_write_keeps_previous_state(self):
        state = offline_state(self, entities={"example.org": ENTITY})
        (state / "cursor").write_text("500")
        real = Path.write_text

        def interrupted(p, data, *a, **kw):  # half the bytes land, then the process is gone
            real(p, data[: len(data) // 2], *a, **kw)
            raise KeyboardInterrupt

        with mock.patch.object(Path, "write_text", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                resolve.main()
        self.assertEqual(json.loads((state / "entities.json").read_text())["example.org"]["org"], "Example Org")
        self.assertEqual((state / "cursor").read_text(), "500")
        self.assertEqual(resolve.main(), 0)  # and the next run goes through


if __name__ == "__main__":
    unittest.main()
