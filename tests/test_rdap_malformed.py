"""An RDAP answer in a shape the parser does not expect is absent evidence, not a crash:
a crash leaves the cursor where it was, so every later run retries the same domain
and crashes again, and nothing is rolled up from then on."""
import unittest
from unittest import mock

import resolve
from _fixture import offline_state, rows

# A registrar entity whose vCard property has no value (jCard requires one; not every server obliges).
MALFORMED = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text"]]]}]}


class MalformedRdap(unittest.TestCase):
    def test_run_completes_and_cursor_advances(self):
        state = offline_state(self)
        with mock.patch.object(resolve, "_get_json", lambda url: MALFORMED):
            self.assertEqual(resolve.main(), 0)
        self.assertTrue((state / "cursor").read_text())
        [row] = rows(state)
        self.assertEqual((row["domain"], row["by"], row["tls"]), ("example.org", "fallback", 1))

    def test_non_string_ip_owner_name_is_absent(self):
        # An IP RDAP answer whose "name" is not a string must not reach _same_org.
        state = offline_state(self)
        with mock.patch.object(resolve, "_get_json", lambda url: {"name": ["x"]}):
            self.assertEqual(resolve.main(), 0)
        self.assertTrue((state / "cursor").read_text())


if __name__ == "__main__":
    unittest.main()
