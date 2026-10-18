#!/usr/bin/env python3
"""Technical gateway startup diagnostic. Dummy token; zero alert reads."""

import os
import re
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from probe import GATEWAY_IMAGE, GITHUB_MCP_IMAGE, NoopSink, ProbeError
from probe import port, pull_and_verify, start_gateway, stop_gateway


DUMMY_TOKEN = "DUMMY_MSRCLAB_STARTUP_ONLY_NO_GITHUB_ACCESS"
REPO = "example/example"
REDACT = re.compile(r"(?i)(?:gh[oprsu]_[A-Za-z0-9_]{20,}|Bearer\s+\S+|Authorization\s*[:=]\s*\S+)")
INTERESTING = ("error", "fail", "valid", "fatal", "gateway", "github", "safeoutputs", "guard")


def scrub(line):
    line = line.replace(DUMMY_TOKEN, "<DUMMY_TOKEN>")
    line = REDACT.sub("<TOKEN_REDACTED>", line)
    return line[:500]


def main():
    if os.environ.get("GITHUB_REPOSITORY") != "8e88no12-creator/msrc-dexter-private-context-lab-20261018":
        raise RuntimeError("wrong_owned_repository")
    if Path(".msrc-private/dexter-canary.txt").exists():
        raise RuntimeError("private_canary_file_unexpected")
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        raise RuntimeError("live_token_environment_unexpected")
    pull_and_verify(GATEWAY_IMAGE)
    pull_and_verify(GITHUB_MCP_IMAGE)
    sink = ThreadingHTTPServer(("0.0.0.0", port()), NoopSink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="msrc-dummy-gateway-", dir=os.environ.get("RUNNER_TEMP")) as directory:
            logs = Path(directory)
            try:
                process, name, _, _ = start_gateway(REPO, DUMMY_TOKEN,
                    sink.server_address[1], logs, "startup")
            except ProbeError as exc:
                print("MSRC_STARTUP_DIAG_CATEGORY " + exc.category, flush=True)
            else:
                print("MSRC_STARTUP_DIAG_CATEGORY healthy", flush=True)
                stop_gateway(process, name)
            for filename in ("startup-process-output.bin", "mcp-gateway.log"):
                path = logs / filename
                if not path.is_file() or path.is_symlink():
                    continue
                print("MSRC_STARTUP_DIAG_FILE " + filename + " " + str(path.stat().st_size), flush=True)
                lines = path.read_text(errors="replace").splitlines()
                selected = [scrub(line) for line in lines if any(word in line.lower() for word in INTERESTING)]
                for line in selected[-50:]:
                    print("MSRC_STARTUP_DIAG_LINE " + line, flush=True)
    finally:
        sink.shutdown()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("MSRC_STARTUP_DIAG_FAILURE " + type(exc).__name__, flush=True)
        raise SystemExit(1)
