"""openssl's -nameopt RFC2253 escapes every byte of a non-ASCII character as \\XX;
the certificate's O= must come back as the organisation's name, not as hex."""
import unittest

import resolve


class Rfc2253(unittest.TestCase):
    def test_hex_escaped_utf8_is_decoded(self):
        # Verbatim from `openssl x509 -noout -subject -nameopt RFC2253` (OpenSSL 3.0).
        dn = r"C=FR,O=Soci\C3\A9t\C3\A9 G\C3\A9n\C3\A9rale\, SA,CN=x.example"
        self.assertEqual(resolve._rfc2253_parts(dn), ["C=FR", "O=Société Générale, SA", "CN=x.example"])

    def test_escaped_specials_still_literal(self):
        self.assertEqual(resolve._rfc2253_parts(r"O=Datadog\, Inc.,CN=a\+b\\AB"), ["O=Datadog, Inc.", r"CN=a+b\AB"])


if __name__ == "__main__":
    unittest.main()
