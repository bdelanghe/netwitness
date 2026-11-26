import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import resolve


def offline_state(test, entities=None, known=None):
    """A state dir, one TLS handshake to www.example.org in zeek logs, and no network."""
    d = Path(tempfile.mkdtemp())
    state, zeek = d / "state", d / "zeek"
    state.mkdir()
    zeek.mkdir()
    (zeek / "ssl.log").write_text(json.dumps({"ts": 1000.0, "server_name": "www.example.org", "id.resp_h": "192.0.2.1"}) + "\n")
    if entities is not None:
        (state / "entities.json").write_text(json.dumps(entities))
    (d / "known.json").write_text(json.dumps(known or {}))
    for name, value in dict(STATE=state, ZEEK=zeek, KNOWN=d / "known.json", RDAP_DELAY=0,
                            cert_org=lambda h: None, jsonld_org=lambda h: (None, []),
                            _get_json=lambda u: None, dmarc_rua_domains=lambda d: []).items():
        p = mock.patch.object(resolve, name, value)
        p.start()
        test.addCleanup(p.stop)
    return state


def rows(state):
    return [json.loads(l) for l in (state / "web-entities.jsonl").read_text().splitlines()]
