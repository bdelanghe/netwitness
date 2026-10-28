{ config, lib, pkgs, ... }:

# netwitness: what this Mac talks to, as three opt-in parts.
#   programs.netwitness.tools.enable    — the CLI half: tshark, termshark, bandwhich, sniffnet, dnstop, mitmproxy, `domains`.
#   programs.netwitness.capture.enable  — zeek on the default interface, always on: conn/dns/ssl logs as JSON, short retention.
#   programs.netwitness.entities.enable — every 15 minutes, resolve the captured domains to organisations and roll them up.
# Capture → resolve → join; this module is the first two stages.
let
  cfg = config.programs.netwitness;

  # `domains [iface]`: every TLS handshake on the default interface as
  # time, destination, SNI hostname — the "what is this machine talking to"
  # feed with nothing else. Needs /dev/bpf* readable (a root launchd daemon
  # that chmods /dev/bpf* at boot, e.g. Wireshark's ChmodBPF); until then, run
  # it under sudo by absolute path.
  domains = pkgs.writeShellScriptBin "domains" ''
    set -eu
    iface="''${1:-$(/sbin/route -n get default | /usr/bin/awk '/interface:/{print $2}')}"
    exec ${pkgs.wireshark-cli}/bin/tshark -i "$iface" -l \
      -f 'port 443' \
      -Y 'tls.handshake.type == 1' \
      -T fields -e frame.time -e ip.dst -e tls.handshake.extensions_server_name
  '';

  # Continuous capture of what this machine talks to: Zeek on the default
  # interface, writing conn.log, dns.log, ssl.log (SNI and certificate
  # subject per TLS connection) and the rest as JSON lines into a state
  # directory. This is the durable form of netmon's `domains` — the same
  # facts, but always on, with history, and machine-readable. It is stage
  # one of three: capture here, resolve each domain to the organisation
  # behind it (next), join the result with other samples by time (after).
  #
  # What it records: every connection's endpoints, every DNS query, every
  # TLS server name — for every process on the machine, not just browsers.
  # That is the point, and it is also why retention is short and the
  # directory is this user's own: `retentionDays` below, nothing copied
  # anywhere. Bodies and URLs are never in here; they are inside TLS.
  #
  # Needs /dev/bpf* readable (see the tools note). Before that, zeek exits
  # with EACCES and launchd retries every ThrottleInterval; agent.log says so.
  zeekState = "${config.xdg.stateHome}/zeek";
  retentionDays = cfg.capture.retentionDays;

  # Brew's zeek by default, not nixpkgs'. nixpkgs' zeek 7.2.2 on
  # aarch64-darwin segfaulted before doing anything — `zeek --version` exits
  # 139, crash report in libhilti's regex compiler — so the default is brew's
  # path. The day `nix run nixpkgs#zeek -- --version` prints a version, set
  # capture.zeekBin = "${pkgs.zeek}/bin/zeek".
  zeekBin = cfg.capture.zeekBin;

  start = pkgs.writeShellScript "zeek-capture" ''
    set -eu
    mkdir -p "${zeekState}"
    cd "${zeekState}"
    # Rotated logs older than the retention window. Zeek rotates by
    # renaming into this same directory (conn-YYYY-MM-DD-HH-MM-SS.log), so
    # one find covers every stream. Runs at each (re)start, which with
    # hourly rotation is often enough.
    /usr/bin/find . -maxdepth 1 -name '*-????-??-??-??-??-??.log' -mtime +${toString retentionDays} -delete
    # The default-route interface, decided at start. A VPN or a Wi-Fi/wired
    # change moves the default route; KeepAlive brings zeek back on the new
    # one the next time it exits, and until then a capture on the old
    # interface is quiet rather than wrong.
    iface=$(/sbin/route -n get default | /usr/bin/awk '/interface:/{print $2}')
    [ -x "${zeekBin}" ] || { echo "zeek-capture: ${zeekBin} missing — brew's zeek not installed yet" >&2; exit 1; }
    exec ${zeekBin} -i "$iface" -C \
      LogAscii::use_json=T \
      Log::default_rotation_interval=1hr
  '';

  # Stage two of capture -> resolve -> join: turn the domains in zeek's logs
  # (the capture agent above) into organisations, and roll them up per
  # interval. The resolver and its evidence order
  # — certificate subject, registrant, address-block owner, a curated list,
  # then the bare domain — are documented in src/resolve.py; the
  # short version is that whois is redacted for everyone, so the answer is
  # assembled from what the connection itself reveals plus a hand-kept
  # map (`entities.knownFile`) for the rest.
  #
  # Every 15 minutes, on the closed 15-minute intervals since the cursor.
  # A domain costs a few network requests the first time and nothing for
  # 30 days after; the roll-up costs nothing. Output is
  # ~/.local/state/web-entities/web-entities.jsonl, one line per (interval,
  # registrable domain): org, confidence, how it was decided, and the TLS
  # handshakes, DNS queries, connections and bytes in that interval. That
  # file is what a stage three joins to other samples by time.
  weState = "${config.xdg.stateHome}/web-entities";
  python = pkgs.python3.withPackages (ps: [ ps.tldextract ]);
  src = ../src;
  known = cfg.entities.knownFile;
in
{
  options.programs.netwitness = {
    tools.enable = lib.mkEnableOption "the network observability CLI tools (tshark, termshark, bandwhich, sniffnet, dnstop, mitmproxy, domains)";
    capture = {
      enable = lib.mkEnableOption "the zeek-capture LaunchAgent (continuous capture on the default interface; needs /dev/bpf* readable)";
      zeekBin = lib.mkOption { type = lib.types.str; default = "/opt/homebrew/bin/zeek"; description = "The zeek binary the agent runs (brew's by default; see the module header)."; };
      retentionDays = lib.mkOption { type = lib.types.ints.positive; default = 14; description = "Rotated logs older than this are deleted at each (re)start."; };
    };
    entities = {
      enable = lib.mkEnableOption "the web-entities resolver agent (and `web-entities` on PATH)";
      knownFile = lib.mkOption {
        type = lib.types.path;
        default = ../known.example.json;
        description = "Hand-curated registrable domain -> organisation JSON, for domains the automatic evidence cannot name. Keys starting with _ are ignored.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.tools.enable {
    # Machine-wide network observability, the CLI half. "What is this machine
    # talking to, with history" splits into: the domain (DNS query, then the
    # SNI in the TLS ClientHello, plaintext even under TLS 1.3), the address
    # and process (always visible), and the URL and body (only through a
    # trusted MITM, and only for apps that do not pin). These tools cover the
    # first two; the third is mitmproxy, kept for the times it is worth its
    # trade.
    #
    # Two things are NOT nix, on purpose:
    #   - tcpdump, lsof, nettop: Apple's builds stay. Apple's tcpdump has the
    #     pktap pseudo-interface (`-i pktap,all -k NP`), which tags each
    #     packet with its process; nixpkgs' tcpdump would shadow that and
    #     know nothing about it. The one place reaching for nix makes things
    #     worse.
    #   - /dev/bpf permissions: reset every boot, need root, so they belong to
    #     a root launchd daemon in the system layer (nix-darwin). Until then,
    #     every capture below is `sudo "$(command -v tshark)" …` — the
    #     `command -v` because sudo resets PATH and root has no profile.
    #
    # HTTP/3 is UDP 443: filter on `port 443`, not `tcp port 443`, or a growing
    # share of browser traffic is silently missing. The QUIC initial still
    # carries SNI in the clear, and tshark and zeek both read it.
    home.packages = with pkgs; [
      wireshark-cli   # tshark: SNI out of the ClientHello, DNS queries, everything else
      termshark       # a TUI over the same dissectors
      # zeek is NOT here: nixpkgs' build segfaulted on aarch64-darwin (see
      # `capture.zeekBin`); it comes from brew.
      bandwhich       # per-process bandwidth, grouped by remote host, reverse-DNS'd
      sniffnet        # the same picture as a friendlier overview
      dnstop          # DNS queries live, by name
      mitmproxy       # full URLs and bodies; needs its CA trusted (manual, System keychain)
      domains         # the SNI feed, see above
    ];
    })
    (lib.mkIf cfg.capture.enable {
    launchd.agents.zeek-capture = {
      enable = true;
      waitForNixStore = false;
      config = {
        ProgramArguments = [ (toString start) ];
        KeepAlive = true;
        RunAtLoad = true;
        # Without BPF access zeek exits at once; a minute between retries
        # keeps that from being a tight loop in agent.log.
        ThrottleInterval = 60;
        WorkingDirectory = zeekState;
        EnvironmentVariables.PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
        StandardOutPath = "${zeekState}/agent.log";
        StandardErrorPath = "${zeekState}/agent.log";
      };
    };

    home.activation.zeekStateDir =
      config.lib.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "${zeekState}"
      '';
    })
    (lib.mkIf cfg.entities.enable {
    launchd.agents.web-entities = {
      enable = true;
      waitForNixStore = false;
      config = {
        ProgramArguments = [ "${python}/bin/python3" "${src}/resolve.py" ];
        StartInterval = 900;
        EnvironmentVariables = {
          # dig and openssl are Apple's, called by absolute path in the script;
          # PATH is only for python itself.
          PATH = "/usr/bin:/bin";
          WEB_ENTITIES_STATE = weState;
          WEB_ENTITIES_KNOWN = "${known}";
          ZEEK_STATE = zeekState;
          # tldextract must never try to update its suffix list from a launchd
          # agent; the snapshot in the package is the authority (resolve.py
          # also configures this; belt and braces).
          TLDEXTRACT_CACHE = "${weState}/tldextract";
        };
        StandardOutPath = "${weState}/agent.log";
        StandardErrorPath = "${weState}/agent.log";
      };
    };

    # The same resolver on PATH for a hand run: `web-entities` processes the
    # intervals since the cursor exactly as the agent would.
    home.packages = [
      (pkgs.writeShellScriptBin "web-entities" ''
        export WEB_ENTITIES_STATE=${weState} WEB_ENTITIES_KNOWN=${known} ZEEK_STATE=${zeekState}
        exec ${python}/bin/python3 ${src}/resolve.py "$@"
      '')
    ];

    home.activation.webEntitiesStateDir =
      config.lib.dag.entryAfter [ "writeBoundary" ] ''
        mkdir -p "${weState}"
      '';
    })
  ];
}
