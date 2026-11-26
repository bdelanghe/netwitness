"""A robots.txt fetch that never answers must not hang the resolver: launchd starts
no new run of a StartInterval agent while the previous one is still running."""
import socket
import threading
import unittest

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


if __name__ == "__main__":
    unittest.main()
