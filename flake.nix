{
  description = "netwitness: what a Mac talks to — network CLI tools, continuous zeek capture, and a domain-to-organisation resolver (Home Manager module)";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    # Only for the module-eval check; consumers already carry home-manager and should `follows` it.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager }:
    let
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      homeManagerModules.default = import ./nix/module.nix;

      checks = forAll (pkgs:
        {
          # The resolver's roll-up on fixture zeek logs, offline: entities already resolved (and fresh) cost nothing,
          # TLS/DNS/conn counts land in the right 15-minute interval, local names are skipped, the cursor advances.
          resolver = pkgs.runCommand "netwitness-resolver"
            { nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.tldextract ])) pkgs.jq ]; } ''
            export WEB_ENTITIES_STATE=$PWD/state ZEEK_STATE=$PWD/zeek WEB_ENTITIES_KNOWN=${./known.example.json} TLDEXTRACT_CACHE=$PWD/tld
            mkdir -p state zeek
            echo '{"ts":1000.0,"server_name":"api.github.com","id.resp_h":"140.82.1.1"}' > zeek/ssl.log
            echo '{"ts":1001.0,"server_name":"printer.local","id.resp_h":"10.0.0.9"}' >> zeek/ssl.log
            echo '{"ts":1002.0,"query":"github.com"}' > zeek/dns.log
            echo '{"ts":1003.0,"id.resp_h":"140.82.1.1","orig_bytes":10,"resp_bytes":32}' > zeek/conn.log
            echo '{"github.com":{"org":"GitHub, Inc.","confidence":"high","by":"cert","resolved_at":99999999999}}' > state/entities.json
            python3 ${./src/resolve.py}
            row=$(cat state/web-entities.jsonl)
            echo "$row" | jq -e '.ts == 900 and .domain == "github.com" and .org == "GitHub, Inc." and .tls == 1 and .dns == 1 and .conns == 1 and .bytes == 42'
            [ "$(wc -l < state/web-entities.jsonl)" = 1 ]
            ! grep -q printer state/entities.json
            [ -s state/cursor ]
            touch $out
          '';
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          # Under Home Manager: nothing by default; each part emits exactly its own agent / packages.
          module-eval =
            let
              hm = extra: (home-manager.lib.homeManagerConfiguration {
                inherit pkgs;
                modules = [ self.homeManagerModules.default { home = { username = "t"; homeDirectory = "/Users/t"; stateVersion = "24.11"; }; } extra ];
              }).config;
              on = hm { programs.netwitness = { tools.enable = true; capture = { enable = true; retentionDays = 3; }; entities.enable = true; }; };
              off = hm { };
              enabled = c: lib.filter (n: c.launchd.agents.${n}.enable) (lib.attrNames c.launchd.agents);
              cap = on.launchd.agents.zeek-capture.config;
              ent = on.launchd.agents.web-entities.config;
            in
            assert enabled off == [ ];
            assert lib.sort lib.lessThan (enabled on) == [ "web-entities" "zeek-capture" ];
            assert ent.EnvironmentVariables.ZEEK_STATE == "/Users/t/.local/state/zeek" && ent.StartInterval == 900;
            assert lib.any (p: (p.name or "") == "domains") on.home.packages;
            pkgs.runCommand "netwitness-module-eval" { } ''
              grep -q -- '-mtime +3 -delete' ${builtins.head cap.ProgramArguments}
              grep -q 'exec /opt/homebrew/bin/zeek -i "$iface" -C' ${builtins.head cap.ProgramArguments}
              ${pkgs.bash}/bin/bash -n ${builtins.head cap.ProgramArguments}
              touch $out
            '';
        });
    };
}
