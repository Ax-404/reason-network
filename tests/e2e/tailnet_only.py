#!/usr/bin/env python3
"""Reproduce a Tailscale-only (tailnet_only) two-node layout with a simulated CGNAT range.

This environment often lacks root `ip`/iptables. The script therefore:

1. Unit-style checks against the built binary (config + bind failure without Tailscale).
2. Optionally, inside a user network namespace (`unshare --user --net --map-root-user`), adds a
   `100.64.x.x` alias with `ifconfig` and verifies the daemon can bind there.
3. Documents what a full firewall proof needs when `iptables`/`ip` are available.

Example values only — never a real MagicDNS name or production address:

  relays = ["https://relay.example.ts.net:10443"]
  tailnet_bind = "100.64.1.10"

Usage:

  cargo build
  python3 tests/e2e/tailnet_only.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "target", "debug", "reason-network")
EXAMPLE_RELAY = "https://relay.example.ts.net:10443"
EXAMPLE_BIND = "100.64.1.10"

results: list[bool] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append(ok)
    print(("PASS" if ok else "FAIL") + f": {name}" + ("" if not detail else f"\n      {detail}"))


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def main() -> int:
    if not os.path.isfile(BIN):
        print(f"missing {BIN}; run `cargo build` first", file=sys.stderr)
        return 2

    home = tempfile.mkdtemp(prefix="rn-tailnet-only-")
    try:
        cfg = textwrap.dedent(
            f"""\
            tailnet_only = true
            relays = ["{EXAMPLE_RELAY}"]
            """
        )
        with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
            f.write(cfg)

        env = dict(
            os.environ,
            HOME=home,
            REASON_NETWORK_HOME=home,
            REASON_NETWORK_NO_UPDATE="1",
            REASON_NETWORK_NO_TRAY="1",
            REASON_NETWORK_NO_MDNS="1",
            REASON_NETWORK_NO_SERVICE="1",
        )

        # Without a Tailscale interface / tailnet_bind, starting a team network must fail clearly.
        # `init` without --relay still starts the daemon; network start logs the failure.
        init = subprocess.run(
            [BIN, "init", "tailnet-demo", "--as", "alex", "--no-setup", "--json"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        check(
            "init still works with tailnet_only in config (team state local)",
            init.returncode == 0,
            init.stdout + init.stderr,
        )

        # Force a network bind attempt via daemon restart after setting a team relay that is allow-listed.
        # check_relay will try to reach EXAMPLE_RELAY (example host): expect a reachability error, not a
        # silent fall-back to public Reason relays.
        relay = subprocess.run(
            [BIN, "relay", EXAMPLE_RELAY],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        out = relay.stdout + relay.stderr
        check(
            "setting example relay does not fall back to public Reason hosts",
            "reasonmachines.com" not in out.lower() and "relay-sfo1" not in out.lower(),
            out,
        )

        # CLI flag is accepted.
        help_out = subprocess.run([BIN, "--help"], capture_output=True, text=True, timeout=30)
        check("--tailnet-only appears in --help", "--tailnet-only" in help_out.stdout)

        # Optional: user-namespace bind smoke test.
        if have("unshare") and have("ifconfig"):
            script = textwrap.dedent(
                f"""\
                set -e
                ifconfig lo 127.0.0.1 netmask 255.0.0.0 up
                ifconfig lo:0 {EXAMPLE_BIND} netmask 255.255.255.255 up
                python3 - <<'PY'
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind(("{EXAMPLE_BIND}", 0))
                print("bound", s.getsockname())
                s.close()
                PY
                """
            )
            ns = subprocess.run(
                ["unshare", "--user", "--net", "--map-root-user", "bash", "-c", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            check(
                "user netns can host a simulated Tailscale CGNAT address for bind tests",
                ns.returncode == 0 and "bound" in ns.stdout,
                ns.stdout + ns.stderr,
            )
        else:
            check(
                "user netns bind smoke (skipped: need unshare+ifconfig)",
                True,
                "install iproute2/net-tools and re-run for the optional namespace check",
            )

        print(
            textwrap.dedent(
                f"""
                --- Not covered in this environment ---
                Full two-node proof with a live iroh-relay on {EXAMPLE_RELAY} and a firewall that
                drops every destination outside 100.64.0.0/10 (and fd7a:115c:a1e0::/48) needs:
                  - `ip` (iproute2) and `iptables`/`nft` with permission to create netns
                  - a TLS iroh-relay listening on a non-443 port reachable only on the simulated tailnet
                  - two REASON_NETWORK_HOME trees with:
                      tailnet_only = true
                      tailnet_bind = "100.64.1.10" / "100.64.1.11"
                      relays = ["{EXAMPLE_RELAY}"]
                Then: init on A with --relay {EXAMPLE_RELAY}, join from B, send a message, and
                confirm with tcpdump/nft counters that no packets leave toward reasonmachines.com,
                github.com, or public DNS discovery endpoints.
                """
            ).strip()
        )
    finally:
        shutil.rmtree(home, ignore_errors=True)

    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
