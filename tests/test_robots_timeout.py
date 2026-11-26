"""A robots.txt fetch that never answers must not hang the resolver: launchd starts
no new run of a StartInterval agent while the previous one is still running."""
import socket
import threading
import io
import unittest
from unittest import mock

import resolve


class RobotsTimeout(unittest.TestCase):
    def test_silent_server_is_a_refusal_not_a_hang(self):
        # Accepts the TCP connection (the kernel's backlog does) and never says a word.
        srv = socket.socket()
        self.addCleanup(srv.close)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        resolve.ROBOTS_TIMEOUT = 1
        out = []
        t = threading.Thread(target=lambda: out.append(resolve._robots_allows(f"127.0.0.1:{srv.getsockname()[1]}")),
                             daemon=True)
        t.start()
        t.join(15)
        self.assertFalse(t.is_alive(), "robots.txt fetch hung")
        self.assertEqual(out, [False], "a fetch failure reads as refusal")


class RobotsOversized(unittest.TestCase):
    def _allows(self, body: bytes) -> bool:
        self.addCleanup(setattr, resolve, "ROBOTS_BYTES", resolve.ROBOTS_BYTES)
        resolve.ROBOTS_BYTES = 100
        with mock.patch("urllib.request.urlopen", lambda req, timeout: io.BytesIO(body)):
            return resolve._robots_allows("example.org")

    def test_body_over_the_cap_is_a_refusal(self):
        # The Disallow lies past the cap: reading only the first ROBOTS_BYTES would miss it and read as permission.
        body = b"User-agent: *\n" + b"# padding\n" * 20 + b"Disallow: /\n"
        self.assertGreater(len(body), 100)
        self.assertFalse(self._allows(body), "a robots.txt too big to read whole is not consent")

    def test_body_under_the_cap_is_read(self):
        self.assertTrue(self._allows(b"User-agent: *\nDisallow: /private/\n"))
        self.assertFalse(self._allows(b"User-agent: *\nDisallow: /\n"))


if __name__ == "__main__":
    unittest.main()
