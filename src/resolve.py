#!/usr/bin/env python3
"""
web-entities — resolve every domain this machine talked to into the
organisation behind it, from zeek's logs, and roll the result up per
interval for the attention lattice.

Stage two of capture -> resolve -> join. Stage one is the zeek capture agent
(ssl.log carries the SNI, dns.log the queries, conn.log the bytes); stage
three joins web-entities.jsonl to attention samples by time.

WHY NOT WHOIS
    Registrant data is redacted post-GDPR — the registry's RDAP says
    nothing, the registrar's says "REDACTED REGISTRANT" — the same finding
    as anyone who has tried it. So the evidence for "who is this
    domain" is, in order of strength:

      cert     the TLS certificate's subject O=, fetched from the server
               (OV/EV certificates name the organisation; DV ones do not)
      jsonld   the site's own schema.org Organization: `legalName` or `name`
               from an application/ld+json block on the homepage. Below the
               certificate because a CA validated that and this is
               self-asserted; above the registrant because a registrant is
               usually a privacy proxy, and a name an organisation publishes
               about itself beats a name nobody published
      rdap     the registrant from the registry/registrar, when not redacted
      ipowner  RDAP on the connected IP: the network's registrant, when
               it matches the domain (GitHub's own ASN says "GitHub, Inc.";
               a Cloudflare address says only who fronts it — that is kept
               as host_org, not as the answer)
      known    a hand-curated JSON map (WEB_ENTITIES_KNOWN), for domains
               the automatic evidence cannot name
      fallback the registrable domain itself, confidence "none"

    Every answer carries the evidence that decided it, plus the registrar
    and the DMARC rua domains, which do not name the org but link it.

    `jsonld_same_as` is evidence, not identity. Sites commonly link themselves
    to Wikidata, so a Q-id arrives for free — but the mapping from a legal
    entity to a Wikidata item is not a bijection (a subsidiary may present the
    parent's certificate; a brand is often a separate item; a rename keeps the
    Q-id and drops the name). The registrable domain and the org STRING remain
    the identity; an alignment is an assertion carrying its own provenance.

STATE   $WEB_ENTITIES_STATE (default ~/.local/state/web-entities)
          entities.json      registrable domain -> {org, confidence, evidence…}
          web-entities.jsonl one line per (interval, registrable domain)
          cursor             the last zeek timestamp rolled up
ZEEK    $ZEEK_STATE (default ~/.local/state/zeek)
KNOWN   $WEB_ENTITIES_KNOWN (default: known.json beside this file)

Network use per NEW domain: one TLS connect for the certificate, one or two
RDAP requests (rdap.org bootstrap, then the registrar), one DNS query for
_dmarc, one RDAP request per new IP. Entries refresh after 30 days.
Domains already known cost nothing.
"""
from __future__ import annotations

import glob
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

import tldextract

STATE = Path(os.environ.get("WEB_ENTITIES_STATE", os.path.expanduser("~/.local/state/web-entities")))
ZEEK = Path(os.environ.get("ZEEK_STATE", os.path.expanduser("~/.local/state/zeek")))
KNOWN = Path(os.environ.get("WEB_ENTITIES_KNOWN", Path(__file__).with_name("known.json")))
INTERVAL = int(os.environ.get("WEB_ENTITIES_INTERVAL", "900"))
REFRESH_DAYS = 30
RDAP_DELAY = 1.0
UA = "web-entities/1 (bdelanghe/home; personal machine telemetry)"

# Offline suffix list: no fetch at import, the snapshot shipped with the
# package is the authority. The agent runs on a timer; it must not block.
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)


def registrable(name: str) -> str:
    e = _extract(name.lower().rstrip("."))
    return e.top_domain_under_public_suffix or name.lower()


# ── evidence ────────────────────────────────────────────────────────────────

# Privacy proxies name themselves in the registrant slot; each is a
# company, none is the answer. Grown from what RDAP actually returned.
PRIVACY_WORDS = ("REDACTED", "PRIVACY", "WITHHELD", "PROXY", "NOT DISCLOSED", "DATA PROTECTED", "GDPR",
                 "PRIVATE BY DESIGN", "DOMAIN PROTECTION SERVICES", "DNSTINATION", "DOMAIN MANAGER",
                 "IDENTITY PROTECT", "WHOISGUARD", "CONTACT PRIVACY", "PERFECT PRIVACY")


def _redacted(name: str | None) -> bool:
    return not name or any(w in name.upper() for w in PRIVACY_WORDS)


def _rfc2253_parts(dn: str) -> list[str]:
    r"""Split a DN on unescaped commas; 'O=Datadog\, Inc.' stays one part."""
    parts, cur, esc = [], "", False
    for ch in dn:
        if esc:
            cur += ch; esc = False
        elif ch == "\\":
            esc = True
        elif ch == ",":
            parts.append(cur); cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts]


def _san_matches(host: str, sans: list[str]) -> bool:
    h = host.lower()
    for san in sans:
        san = san.lower()
        if san == h:
            return True
        if san.startswith("*.") and h.count(".") == san.count(".") and h.endswith(san[1:]):
            return True
    return False


def cert_org(host: str) -> str | None:
    """Subject O= of the certificate the server presents for this SNI — but
    only when the certificate is actually for this host. Connecting by name,
    not by the captured address: a relay or CDN address answers for many
    names, and a certificate that does not cover the host is somebody else's."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                der = t.getpeercert(binary_form=True)
    except Exception:
        return None
    try:
        # macOS's openssl is LibreSSL, which has no `-ext`; the SAN list is
        # read out of -text instead.
        out = subprocess.run(["/usr/bin/openssl", "x509", "-inform", "DER", "-noout", "-subject", "-nameopt", "RFC2253",
                              "-text"], input=der, capture_output=True, timeout=5).stdout.decode()
    except Exception:
        return None
    sans = re.findall(r"DNS:([^,\s]+)", out)
    if not _san_matches(host, sans):
        return None
    subject = next((l for l in out.splitlines() if l.startswith("subject=")), "")
    for part in _rfc2253_parts(subject.replace("subject=", "", 1)):
        if part.startswith("O="):
            return part[2:].strip() or None
    return None


JSONLD_BYTES = 512 * 1024
JSONLD_SCRIPT = re.compile(
    rb'<script[^>]+type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def _robots_allows(host: str) -> bool:
    """Ask robots.txt before fetching a page. The other evidence sources here
    are a TLS handshake and API calls to RDAP and DNS — none of which is a
    request for content. This one is, so it asks first. A missing or
    unparseable robots.txt reads as permission, which is the convention; a
    fetch failure reads as refusal, because not knowing is not consent."""
    import urllib.robotparser

    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(f"https://{host}/robots.txt")
    try:
        rp.read()
    except Exception:
        return True
    try:
        return rp.can_fetch(UA, f"https://{host}/")
    except Exception:
        return True


def jsonld_org(host: str) -> tuple[str | None, list[str]]:
    """The organisation as the SITE names itself, from schema.org JSON-LD, plus
    whatever it links itself to.

    The evidence sources above ask third parties about a domain: a CA, a
    registry, a network's registrant. This asks the domain. That is weaker in
    one way — it is self-asserted, and a parked or compromised host can claim
    anything, which is why it ranks below the CA-validated certificate — and
    stronger in another: it is the only source that returns the name the
    organisation actually uses, rather than the legal string on a certificate
    or a registrar's redacted proxy.

    `sameAs` is the interesting half. Sites commonly link themselves to
    Wikidata, and that is a Q-id arriving for free without querying Wikidata at
    all. It is recorded as evidence of what the site CLAIMS, never as identity:
    the canonical string stays the join key, and an alignment is an assertion
    with its own provenance.

    Returns (org name or None, sameAs URIs). Never raises: every failure —
    robots, timeout, TLS, malformed JSON, no Organization node — is absence,
    the same way cert_org and rdap_domain degrade.
    """
    if not _robots_allows(host):
        return None, []
    req = urllib.request.Request(
        f"https://{host}/",
        headers={"Accept": "text/html", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(JSONLD_BYTES)
    except Exception:
        return None, []

    for raw in JSONLD_SCRIPT.findall(body):
        try:
            doc = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            continue
        for node in _jsonld_nodes(doc):
            types = node.get("@type")
            types = types if isinstance(types, list) else [types]
            # Organization and most of its subtypes end in the word —
            # NewsMediaOrganization, EducationalOrganization — so matching the
            # suffix avoids enumerating a vocabulary that keeps growing.
            # Corporation is the notable subtype that does not.
            if not any(
                isinstance(t, str) and (t.endswith("Organization") or t == "Corporation")
                for t in types
            ):
                continue
            name = node.get("legalName") or node.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            same = node.get("sameAs") or []
            same = [same] if isinstance(same, str) else [s for s in same if isinstance(s, str)]
            return name.strip(), same
    return None, []


def _jsonld_nodes(doc):
    """Every object in a JSON-LD document. A page may ship one node, a list, or
    an @graph, and the Organization is as often nested under `publisher` or
    `provider` as it is top level — so this walks rather than pattern-matching
    the three shapes that happen to be common."""
    stack = [doc]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            yield cur
            stack.extend(cur.values())
        elif isinstance(cur, list):
            stack.extend(cur)


def _get_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except Exception:
        return None


ROLE_WORDS = ("ON BEHALF OF", "HOSTMASTER", "ADMINISTRATOR", "REGISTRATION PRIVATE", "OWNER", "DOMAIN ADMIN",
              "DNS ADMIN", "WEBMASTER", "LEGAL DEPT")


def _vcard_fn(entity: dict) -> str | None:
    """The organisation named by a vCard: `org` first (fn is usually a person
    or a role), and a role-like fn — "Domain Administrator", "On behalf of
    x OWNER", "Hostmaster" — is no name at all."""
    props = (entity.get("vcardArray") or [None, []])[1]
    for want in ("org", "fn"):
        for item in props:
            if item and item[0] == want and item[3]:
                v = str(item[3]).strip()
                if v and not any(w in v.upper() for w in ROLE_WORDS):
                    return v
    return None


def rdap_domain(domain: str) -> dict:
    """registrar, and registrant if the registrar's RDAP still exposes it."""
    out: dict = {"registrar": None, "registrant": None}
    reg = _get_json(f"https://rdap.org/domain/{domain}")
    if not reg:
        return out
    for e in reg.get("entities", []):
        if "registrar" in (e.get("roles") or []):
            out["registrar"] = _vcard_fn(e)
    related = [l["href"] for l in reg.get("links", []) if l.get("rel") == "related" and l.get("href")]
    for href in related[:1]:
        time.sleep(RDAP_DELAY)
        rr = _get_json(href)
        if not rr:
            continue
        for e in rr.get("entities", []):
            for ent in [e] + (e.get("entities") or []):
                if "registrant" in (ent.get("roles") or []):
                    fn = _vcard_fn(ent)
                    if not _redacted(fn):
                        out["registrant"] = fn
    return out


def rdap_ip(ip: str) -> str | None:
    """The organisation that holds the address block."""
    r = _get_json(f"https://rdap.org/ip/{ip}")
    if not r:
        return None
    for e in r.get("entities", []):
        if "registrant" in (e.get("roles") or []):
            fn = _vcard_fn(e)
            if fn:
                return fn
    return r.get("name") or None


def dmarc_rua_domains(domain: str) -> list[str]:
    try:
        txt = subprocess.run(["/usr/bin/dig", "+short", "+time=3", "TXT", f"_dmarc.{domain}"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    found = []
    for tag in ("rua=", "ruf="):
        i = txt.find(tag)
        if i < 0:
            continue
        for addr in txt[i + 4:].split(";")[0].split(","):
            addr = addr.strip().strip('"').replace("mailto:", "")
            if "@" in addr:
                d = registrable(addr.split("@", 1)[1].split("!")[0])
                if d not in found:
                    found.append(d)
    return found


def _same_org(domain: str, org: str) -> bool:
    """'GitHub, Inc.' names github.com and githubusercontent.com; 'Apple Inc.'
    names apple-cloudkit.com; 'Cloudflare, Inc.' names none of them."""
    stem = domain.split(".")[0].lower()
    flat = re.sub(r"[^a-z0-9]", "", org.lower())
    first = re.sub(r"[^a-z0-9]", "", org.lower().split()[0]) if org.split() else ""
    tokens = [t for t in stem.split("-") if len(t) >= 4]
    return any(t in flat for t in tokens) or (len(first) >= 4 and stem.startswith(first))


def resolve(domain: str, hosts: dict[str, str], known: dict, ip_cache: dict) -> dict:
    """One registrable domain -> entity record, from the evidence in order."""
    host, ip = next(iter(hosts.items()), (domain, None))
    ev: dict = {}
    ev["cert_o"] = cert_org(host)
    ev["jsonld_org"], ev["jsonld_same_as"] = jsonld_org(host)
    time.sleep(RDAP_DELAY)
    ev.update(rdap_domain(domain))
    if ip:
        if ip not in ip_cache:
            time.sleep(RDAP_DELAY)
            ip_cache[ip] = rdap_ip(ip)
        ev["host_org"] = ip_cache[ip]
    ev["dmarc_rua"] = dmarc_rua_domains(domain)

    if ev.get("cert_o"):
        org, conf, by = ev["cert_o"], "high", "cert"
    # The site's own schema.org Organization. Below the certificate because a
    # CA validated that one and this is self-asserted; above the registrant
    # because a registrant is usually a registrar's privacy proxy, and a name
    # the organisation publishes about itself beats a name nobody published.
    elif ev.get("jsonld_org"):
        org, conf, by = ev["jsonld_org"], "high", "jsonld"
    elif ev.get("registrant"):
        org, conf, by = ev["registrant"], "high", "rdap"
    elif ev.get("host_org") and _same_org(domain, ev["host_org"]):
        org, conf, by = ev["host_org"], "medium", "ipowner"
    elif domain in known:
        org, conf, by = known[domain], "medium", "known"
    else:
        org, conf, by = domain, "none", "fallback"
    return {"org": org, "confidence": conf, "by": by, "evidence": ev, "resolved_at": time.time()}


# ── zeek logs ───────────────────────────────────────────────────────────────

def _lines(pattern: str, since: float):
    """JSON lines from the live file and any rotated ones newer than the cursor."""
    for p in sorted(glob.glob(str(ZEEK / pattern))):
        if os.path.getmtime(p) < since:
            continue
        with open(p) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if d.get("ts", 0) > since:
                    yield d


def collect(since: float, until: float):
    """(registrable -> {host: ip}), and per-interval counters."""
    hosts: dict[str, dict[str, str]] = defaultdict(dict)
    buckets: dict = defaultdict(lambda: defaultdict(lambda: {"tls": 0, "dns": 0, "conns": 0, "bytes": 0}))
    ip_dom: dict[str, str] = {}
    for d in _lines("ssl*.log", since):
        ts = d["ts"]
        if ts > until:
            continue
        sni = d.get("server_name")
        if not sni or "." not in sni or sni.endswith((".local", ".localhost", ".localdomain", ".internal", ".home")):
            continue
        r = registrable(sni)
        hosts[r].setdefault(sni, d.get("id.resp_h"))
        ip_dom[d.get("id.resp_h")] = r
        buckets[int(ts // INTERVAL) * INTERVAL][r]["tls"] += 1
    for d in _lines("dns*.log", since):
        ts = d["ts"]
        q = d.get("query")
        if ts > until or not q or "." not in q or q.endswith((".arpa", ".local", ".localhost", ".localdomain", ".internal", ".home")):
            continue
        r = registrable(q)
        hosts[r].setdefault(q, None)
        buckets[int(ts // INTERVAL) * INTERVAL][r]["dns"] += 1
    for d in _lines("conn*.log", since):
        ts = d["ts"]
        r = ip_dom.get(d.get("id.resp_h"))
        if ts > until or not r:
            continue
        b = buckets[int(ts // INTERVAL) * INTERVAL][r]
        b["conns"] += 1
        b["bytes"] += int(d.get("orig_bytes") or 0) + int(d.get("resp_bytes") or 0)
    return hosts, buckets


def main() -> int:
    STATE.mkdir(parents=True, exist_ok=True)
    ents_p, out_p, cur_p = STATE / "entities.json", STATE / "web-entities.jsonl", STATE / "cursor"
    entities = json.loads(ents_p.read_text()) if ents_p.exists() else {}
    known = {k: v for k, v in (json.loads(KNOWN.read_text()) if KNOWN.exists() else {}).items() if not k.startswith("_")}
    since = float(cur_p.read_text()) if cur_p.exists() else 0.0
    # Only closed intervals: the current one is still filling.
    until = int(time.time() // INTERVAL) * INTERVAL
    if until <= since:
        return 0

    hosts, buckets = collect(since, until)
    ip_cache: dict = {}
    now = time.time()
    fresh = 0
    for r, hs in hosts.items():
        cur = entities.get(r)
        if cur and now - cur.get("resolved_at", 0) < REFRESH_DAYS * 86400:
            continue
        entities[r] = resolve(r, {h: ip for h, ip in hs.items() if ip} or hs, known, ip_cache)
        fresh += 1
    for r in hosts:
        entities[r]["last_seen"] = now
        entities[r].setdefault("first_seen", now)

    with open(out_p, "a") as f:
        for start in sorted(buckets):
            for r, c in sorted(buckets[start].items()):
                e = entities.get(r, {})
                f.write(json.dumps({"ts": start, "interval": INTERVAL, "domain": r, "org": e.get("org", r),
                                    "confidence": e.get("confidence", "none"), "by": e.get("by", "fallback"), **c}) + "\n")
    ents_p.write_text(json.dumps(entities, indent=1, sort_keys=True))
    cur_p.write_text(str(until))
    print(f"web-entities: {len(hosts)} domains in ({since:.0f}, {until}], {fresh} resolved, "
          f"{sum(len(b) for b in buckets.values())} rows written", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
