# netwitness

What a Mac talks to, as a Home Manager module with three opt-in parts (capture → resolve; a "join" stage is yours):

| option | what |
|---|---|
| `programs.netwitness.tools.enable` | tshark, termshark, bandwhich, sniffnet, dnstop, mitmproxy, and `domains` (every TLS ClientHello's SNI, live). Apple's tcpdump/lsof/nettop are left alone (Apple's tcpdump has `pktap`). |
| `programs.netwitness.capture.enable` | zeek on the default interface, always on: conn/dns/ssl logs as JSON lines in `~/.local/state/zeek`, rotated hourly, kept `retentionDays` (14). Endpoints, DNS queries and TLS server names for every process — never bodies or URLs. |
| `programs.netwitness.entities.enable` | every 15 minutes, resolve each captured registrable domain to an organisation (TLS certificate O=, the site's schema.org Organization, RDAP registrant, IP-block owner, your `knownFile`, then the bare domain) and write one line per (interval, domain) to `~/.local/state/web-entities/web-entities.jsonl`. |

Capture needs `/dev/bpf*` readable (a root launchd daemon in the system layer, e.g. Wireshark's ChmodBPF or a
nix-darwin equivalent). zeek defaults to brew's (`capture.zeekBin`): nixpkgs' zeek 7.2.2 segfaulted on aarch64-darwin.
HTTP/3 is UDP 443 — the filters use `port 443`, not `tcp port 443`.

```nix
inputs.netwitness = { url = "github:bdelanghe/netwitness"; inputs.nixpkgs.follows = "nixpkgs"; inputs.home-manager.follows = "home-manager"; };
# modules = [ netwitness.homeManagerModules.default ];
programs.netwitness = { tools.enable = true; capture.enable = true; entities = { enable = true; knownFile = ./known.json; }; };
```

## Checks

`nix flake check`: the resolver's roll-up on fixture zeek logs, offline (any system); on macOS the module under Home Manager.
