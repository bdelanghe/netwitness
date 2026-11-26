"""A line added to knownFile names a domain the resolver fell back on — from the next
run, not after the fallback's 30-day refresh."""
import unittest

import resolve
from _fixture import offline_state, rows

FALLBACK = {"org": "example.org", "confidence": "none", "by": "fallback", "resolved_at": 99999999999}


class KnownApplies(unittest.TestCase):
    def test_known_overrides_fresh_fallback(self):
        state = offline_state(self, entities={"example.org": FALLBACK}, known={"example.org": "Example Org"})
        self.assertEqual(resolve.main(), 0)
        [row] = rows(state)
        self.assertEqual((row["org"], row["confidence"], row["by"]), ("Example Org", "medium", "known"))

    def test_known_does_not_override_stronger_evidence(self):
        cert = dict(FALLBACK, org="Example Org, Inc.", confidence="high", by="cert")
        state = offline_state(self, entities={"example.org": cert}, known={"example.org": "Example Org"})
        self.assertEqual(resolve.main(), 0)
        [row] = rows(state)
        self.assertEqual((row["org"], row["by"]), ("Example Org, Inc.", "cert"))


if __name__ == "__main__":
    unittest.main()
