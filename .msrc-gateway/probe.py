#!/usr/bin/env python3
"""Owned-lab, hash-only Dexter gateway read probe.

This runs the exact pinned gateway and GitHub MCP server images. It never
prints, writes, or uploads the dismissed_comment or an MCP tool response.
"""

import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


GATEWAY_IMAGE = (
    "ghcr.io/github/gh-aw-mcpg:v0.4.25@"
    "sha256:9be0a86220e807a0ecc89e53d7453468f7a53fbc6b3d1efd2299025ffe01d086"
)
GITHUB_MCP_IMAGE = (
    "ghcr.io/github/github-mcp-server:v1.12.2@"
    "sha256:508a0857ec762b1ab1cece29193345b501fab1dd9d1228a7b617062954cecac6"
)
GITHUB_MCP_RUNTIME_IMAGE = "ghcr.io/github/github-mcp-server:v1.12.2"
ALERT_NUMBER = 5
NULL_LOG_NAMES = (
    "mcp-gateway.log", "rpc-messages.jsonl", "gateway.md",
    "github.log", "safeoutputs.log",
)
CURRENT_STAGE = "entry"


class ProbeError(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def api_get(url, token):
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "msrc-owned-lab-gateway-probe",
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (urllib.error.URLError, ValueError, OSError):
            if attempt < 2:
                time.sleep(0.5)
    return 0, None


def pull_and_verify(image):
    done = subprocess.run(["docker", "pull", image], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=240, check=False)
    if done.returncode:
        raise ProbeError("image_pull_failed")
    inspect = subprocess.run(["docker", "image", "inspect", "--format",
                              "{{json .RepoDigests}}", image], capture_output=True,
                             text=True, timeout=20, check=False)
    if inspect.returncode:
        raise ProbeError("image_inspect_failed")
    try:
        digests = json.loads(inspect.stdout)
    except ValueError:
        raise ProbeError("image_inspect_invalid") from None
    expected = image.split("@", 1)[1]
    if not any(item.endswith("@" + expected) for item in digests):
        raise ProbeError("image_digest_mismatch")


def image_id(image):
    inspect = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                             capture_output=True, text=True, timeout=20, check=False)
    if inspect.returncode or not inspect.stdout.strip().startswith("sha256:"):
        raise ProbeError("image_id_inspect_failed")
    return inspect.stdout.strip()


def pin_local_mcp_tag():
    # The pinned v0.4.25 config schema accepts a tag but rejects @sha256 in
    # mcpServers.github.container. Bind the schema-compatible tag to the exact
    # verified digest on this isolated runner before launching the gateway.
    tagged = subprocess.run(["docker", "tag", GITHUB_MCP_IMAGE, GITHUB_MCP_RUNTIME_IMAGE],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=20, check=False)
    if tagged.returncode or image_id(GITHUB_MCP_IMAGE) != image_id(GITHUB_MCP_RUNTIME_IMAGE):
        raise ProbeError("github_mcp_tag_pin_failed")


class NoopSink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    tool_calls = 0

    def log_message(self, *_args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        try:
            request = json.loads(self.rfile.read(size) or b"{}")
        except ValueError:
            self.reply(400, {"error": "invalid_json"})
            return
        method = request.get("method")
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "owned-lab-noop-sink", "version": "1.0"}}
        elif method in ("tools/list", "server/discover"):
            result = {"tools": []}
        elif method == "tools/call":
            type(self).tool_calls += 1
            self.reply(200, {"jsonrpc": "2.0", "id": request.get("id"),
                             "error": {"code": -32601, "message": "no_tools"}})
            return
        else:
            self.reply(200, {"jsonrpc": "2.0", "id": request.get("id"),
                             "error": {"code": -32601, "message": "no_method"}})
            return
        self.reply(200, {"jsonrpc": "2.0", "id": request.get("id"), "result": result})

    def reply(self, status, data):
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def config(agent_id, sink_port):
    return {
        "mcpServers": {
            "github": {
                "type": "stdio", "container": GITHUB_MCP_RUNTIME_IMAGE,
                "env": {
                    "GITHUB_FEATURES": "fields_param",
                    "GITHUB_HOST": "${GITHUB_SERVER_URL}",
                    "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}",
                    "GITHUB_READ_ONLY": "1",
                    "GITHUB_TOOLSETS": "context,repos,pull_requests,actions,dependabot",
                },
                "guard-policies": {"allow-only": {
                    "approval-labels": [], "blocked-users": [],
                    "min-integrity": "unapproved", "repos": "all",
                    "trusted-users": [],
                }},
            },
            "safeoutputs": {
                "type": "http",
                "url": f"http://host.docker.internal:{sink_port}/safeoutputs",
                "guard-policies": {"write-sink": {
                    "accept": ["*"], "sink-visibility": "public",
                }},
            },
        },
        "gateway": {"port": 8080, "domain": "awmg-mcpg", "agentId": agent_id},
    }


def startup_exit_category(logs, returncode):
    # Startup instance has not called an alert tool. Inspect output in memory;
    # emit only a fixed category, never process text or config values.
    parts = []
    for filename in ("startup-process-output.bin", "mcp-gateway.log"):
        path = logs / filename
        if path.is_file() and not path.is_symlink():
            parts.append(path.read_bytes()[:1048576].lower())
    output = b"\n".join(parts)
    patterns = (
        (b"configuration validation error", "config_schema_validation"),
        (b"environment validation failed", "environment_validation"),
        (b"environment validation passed", "after_environment_validation"),
        (b"unknown flag", "unknown_flag"),
        (b"invalid config", "invalid_config"),
        (b"permission denied", "permission_denied"),
        (b"cannot connect to the docker daemon", "docker_unavailable"),
        (b"no such host", "dns_failure"),
        (b"connection refused", "upstream_refused"),
        (b"failed to start", "start_failure"),
    )
    for needle, category in patterns:
        if needle in output:
            return "gateway_exit_" + category
    if isinstance(returncode, int):
        return "gateway_exit_code_" + str(abs(returncode))
    return "gateway_exited_before_health"


def start_gateway(repository, token, sink_port, logs, label):
    host_port = port()
    agent_id = secrets.token_urlsafe(30)
    name = f"msrc-dexter-probe-{label}-{os.getpid()}"
    env = os.environ.copy()
    env["GITHUB_TOKEN"] = token
    env["GITHUB_REPOSITORY"] = repository
    env["GITHUB_SERVER_URL"] = "https://github.com"
    payloads = logs / "payloads"
    payloads.mkdir(exist_ok=True)
    command = [
        "docker", "run", "--rm", "-i", "--name", name,
        "--network", "bridge", "--add-host", "host.docker.internal:host-gateway",
        "-p", f"127.0.0.1:{host_port}:8080",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{logs}:/tmp/gh-aw/mcp-logs:rw",
        "-v", f"{payloads}:/tmp/gh-aw/mcp-payloads:rw",
        "-e", "GITHUB_TOKEN", "-e", "GITHUB_REPOSITORY", "-e", "GITHUB_SERVER_URL",
        "-e", "MCP_GATEWAY_PORT=8080", "-e", "MCP_GATEWAY_DOMAIN=awmg-mcpg",
        "-e", f"MCP_GATEWAY_AGENT_ID={agent_id}",
        "-e", "MCP_GATEWAY_PAYLOAD_DIR=/tmp/gh-aw/mcp-payloads",
        "-e", "MCP_GATEWAY_PAYLOAD_SIZE_THRESHOLD=524288",
        "-e", "MCP_GATEWAY_LOG_DIR=/tmp/gh-aw/mcp-logs",
        GATEWAY_IMAGE,
    ]
    stream = (logs / "startup-process-output.bin").open("wb") if label == "startup" else subprocess.DEVNULL
    try:
        process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                   stdout=stream, stderr=stream)
    finally:
        if stream is not subprocess.DEVNULL:
            stream.close()
    try:
        process.stdin.write(json.dumps(config(agent_id, sink_port)).encode())
        process.stdin.close()
    except (BrokenPipeError, OSError):
        stop_gateway(process, name)
        raise ProbeError("gateway_config_pipe_failed") from None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stop_gateway(process, name)
            if label == "startup":
                raise ProbeError(startup_exit_category(logs, process.returncode))
            raise ProbeError("read_gateway_exited_before_health")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{host_port}/health", timeout=2) as response:
                if response.status == 200:
                    return process, name, host_port, agent_id
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(0.4)
    stop_gateway(process, name)
    raise ProbeError("gateway_health_timeout")


def stop_gateway(process, name):
    subprocess.run(["docker", "stop", "--time", "2", name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=12, check=False)
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def startup_markers(logs):
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        text = "\n".join(
            (logs / name).read_text(errors="replace")
            for name in ("mcp-gateway.log", "github.log", "safeoutputs.log")
            if (logs / name).exists()
        )
        markers = {
            "wasm_guard_loaded": "Loaded discovered WASM guard from file" in text,
            "force_public_repos": "FORCED REPOS=PUBLIC" in text,
            "force_public_fail_open": "fail-open, not forcing repos=public" in text,
            "public_sink_guard": 'Created write-sink guard with 1 accept patterns, sink-visibility="public"' in text,
        }
        if markers["wasm_guard_loaded"] and markers["force_public_repos"] and markers["public_sink_guard"]:
            return markers
        time.sleep(0.3)
    return markers


def parse_rpc(body):
    if not body.strip():
        return {}
    text = body.decode(errors="replace")
    if "data:" in text:
        lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        if lines:
            return json.loads(lines[-1])
    return json.loads(text)


def rpc(host_port, agent_id, session, method, params=None, request_id=None):
    obj = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        obj["id"] = request_id
    if params is not None:
        obj["params"] = params
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream",
               "Authorization": agent_id}
    if session:
        headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(f"http://127.0.0.1:{host_port}/mcp/github",
                                     data=json.dumps(obj).encode(), headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=35) as response:
            return response.status, response.headers.get("Mcp-Session-Id", session), parse_rpc(response.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, session, parse_rpc(exc.read())
        except ValueError:
            return exc.code, session, {}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        raise ProbeError("gateway_rpc_transport_failed_at_" + CURRENT_STAGE) from None


def find_comments(obj, depth=0):
    if depth > 10:
        return []
    if isinstance(obj, dict):
        values = [obj["dismissed_comment"]] if isinstance(obj.get("dismissed_comment"), str) else []
        for value in obj.values():
            values.extend(find_comments(value, depth + 1))
        return values
    if isinstance(obj, list):
        return [comment for item in obj for comment in find_comments(item, depth + 1)]
    if isinstance(obj, str) and obj[:1] in ("{", "["):
        try:
            return find_comments(json.loads(obj), depth + 1)
        except ValueError:
            return []
    return []


def classify_read(response, expected_hash):
    matching = any(hashlib.sha256(value.encode()).hexdigest() == expected_hash
                   for value in find_comments(response))
    if matching:
        return "returned_matching_private_comment", True
    if "[Filtered]" in response.get("error", {}).get("message", ""):
        return "filtered_by_gateway", False
    if "error" in response:
        return "other_gateway_error", False
    return "returned_without_matching_comment", False


def verify_null_logs(logs):
    return all((logs / name).is_symlink() and os.readlink(logs / name) == "/dev/null"
               for name in NULL_LOG_NAMES)


def scan_private_scratch(logs, comment):
    # Gateway container runs as root. Its ordinary scratch files can be 0600.
    # Stop it first, then make only this ephemeral runner directory readable.
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
    if (not runner_temp.is_dir() or not logs.resolve().is_relative_to(runner_temp)
            or not logs.name.startswith("msrc-gateway-null-")):
        raise ProbeError("scratch_log_path_invalid")
    owner = f"{os.getuid()}:{os.getgid()}"
    changed = subprocess.run(["sudo", "-n", "chown", "-hR", owner, str(logs)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             timeout=20, check=False)
    if changed.returncode:
        raise ProbeError("scratch_log_access_failed")
    try:
        return any(comment.encode() in path.read_bytes()
                   for path in logs.rglob("*") if path.is_file() and not path.is_symlink())
    except OSError:
        raise ProbeError("scratch_log_access_failed") from None


def run():
    global CURRENT_STAGE
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN", "")
    expected = os.environ.get("EXPECTED_SHA256", "").lower()
    if repository != "8e88no12-creator/msrc-dexter-private-context-lab-20261018":
        raise ProbeError("wrong_owned_repository")
    if not token or len(expected) != 64:
        raise ProbeError("missing_auth_or_expected_hash")

    CURRENT_STAGE = "repo_visibility_preflight"
    repo_status, repo_data = api_get(f"https://api.github.com/repos/{repository}", token)
    if repo_status != 200 or not isinstance(repo_data, dict):
        raise ProbeError("repo_visibility_preflight_failed")
    visibility = repo_data.get("visibility")
    if visibility != "public" or repo_data.get("private") is not False:
        raise ProbeError("repo_visibility_not_public")
    CURRENT_STAGE = "alert_preflight"
    alert_status, alert_data = api_get(
        f"https://api.github.com/repos/{repository}/dependabot/alerts/{ALERT_NUMBER}", token)
    if alert_status != 200 or not isinstance(alert_data, dict):
        raise ProbeError("alert_preflight_failed")
    comment = alert_data.get("dismissed_comment")
    if not isinstance(comment, str) or hashlib.sha256(comment.encode()).hexdigest() != expected:
        raise ProbeError("alert_hash_preflight_failed")

    CURRENT_STAGE = "gateway_image_pull"
    pull_and_verify(GATEWAY_IMAGE)
    CURRENT_STAGE = "github_mcp_image_pull"
    pull_and_verify(GITHUB_MCP_IMAGE)
    CURRENT_STAGE = "github_mcp_tag_pin"
    pin_local_mcp_tag()

    sink = ThreadingHTTPServer(("0.0.0.0", port()), NoopSink)
    sink_port = sink.server_address[1]
    threading.Thread(target=sink.serve_forever, daemon=True).start()
    try:
        # Startup-only instance provides direct effective-policy markers before
        # any private alert call. Its logs remain runner-private and are deleted.
        CURRENT_STAGE = "startup_gateway"
        with tempfile.TemporaryDirectory(prefix="msrc-gateway-startup-", dir=os.environ.get("RUNNER_TEMP")) as directory:
            logs = Path(directory)
            process, name, _, _ = start_gateway(repository, token, sink_port, logs, "startup")
            try:
                markers = startup_markers(logs)
            finally:
                stop_gateway(process, name)
        if not all((markers["wasm_guard_loaded"], markers["force_public_repos"], markers["public_sink_guard"])):
            raise ProbeError("effective_public_guard_unconfirmed")
        if markers["force_public_fail_open"]:
            raise ProbeError("visibility_lookup_failed_open")

        # Sensitive instance: every content-bearing gateway log is /dev/null.
        CURRENT_STAGE = "read_gateway"
        with tempfile.TemporaryDirectory(prefix="msrc-gateway-null-", dir=os.environ.get("RUNNER_TEMP")) as directory:
            logs = Path(directory)
            for filename in NULL_LOG_NAMES:
                (logs / filename).symlink_to("/dev/null")
            process, name, host_port, agent_id = start_gateway(repository, token, sink_port, logs, "read")
            try:
                if not verify_null_logs(logs):
                    raise ProbeError("null_log_guard_before_read_failed")
                CURRENT_STAGE = "read_gateway_initialize"
                status, session, initialized = rpc(host_port, agent_id, None, "initialize",
                    {"protocolVersion": "2024-11-05", "capabilities": {},
                     "clientInfo": {"name": "owned-lab-read-probe", "version": "1.0"}}, 1)
                if status != 200 or "result" not in initialized:
                    raise ProbeError("gateway_initialize_failed")
                rpc(host_port, agent_id, session, "notifications/initialized")
                CURRENT_STAGE = "read_gateway_tools_list"
                _, session, listed = rpc(host_port, agent_id, session, "tools/list", {}, 2)
                names = [tool.get("name", "") for tool in listed.get("result", {}).get("tools", [])]
                get_tool = next((name for name in names if name.endswith("get_dependabot_alert")), None)
                list_tool = next((name for name in names if name.endswith("list_dependabot_alerts")), None)
                if get_tool is None or list_tool is None:
                    raise ProbeError("dependabot_tools_missing")
                CURRENT_STAGE = "read_gateway_get_alert"
                get_http, session, get_response = rpc(host_port, agent_id, session, "tools/call",
                    {"name": get_tool, "arguments": {
                        "owner": repository.split("/", 1)[0],
                        "repo": repository.split("/", 1)[1],
                        "alertNumber": ALERT_NUMBER,
                    }}, 3)
                get_category, get_hash_match = classify_read(get_response, expected)
                CURRENT_STAGE = "read_gateway_list_alerts"
                list_http, session, list_response = rpc(host_port, agent_id, session, "tools/call",
                    {"name": list_tool, "arguments": {
                        "owner": repository.split("/", 1)[0],
                        "repo": repository.split("/", 1)[1],
                        "state": "dismissed",
                    }}, 4)
                list_category, list_hash_match = classify_read(list_response, expected)
                if not verify_null_logs(logs):
                    raise ProbeError("null_log_guard_after_read_failed")
            finally:
                stop_gateway(process, name)
            CURRENT_STAGE = "scratch_log_scan"
            if not verify_null_logs(logs):
                raise ProbeError("null_log_guard_after_stop_failed")
            # No full response or gateway log is copied to Actions output.
            if scan_private_scratch(logs, comment):
                raise ProbeError("private_comment_in_scratch_log")
    finally:
        sink.shutdown()

    tag_match_after_read = image_id(GITHUB_MCP_IMAGE) == image_id(GITHUB_MCP_RUNTIME_IMAGE)
    if not tag_match_after_read:
        raise ProbeError("github_mcp_tag_drift")
    receipt = {
        "kind": "owned_lab_gateway_read_only",
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "source_sha": os.environ.get("GITHUB_SHA"),
        "gateway_image_digest": GATEWAY_IMAGE.split("@", 1)[1],
        "github_mcp_image_digest": GITHUB_MCP_IMAGE.split("@", 1)[1],
        "github_mcp_tag_match_after_read": tag_match_after_read,
        "repo_visibility_http": repo_status,
        "repo_visibility": visibility,
        "alert_http": alert_status,
        "direct_alert_hash_match": True,
        "gateway_wasm_loaded": markers["wasm_guard_loaded"],
        "startup_instance_force_public_repos": markers["force_public_repos"],
        "public_sink_guard_configured": markers["public_sink_guard"],
        "gateway_get_http": get_http,
        "gateway_get_category": get_category,
        "gateway_get_comment_hash_match": get_hash_match,
        "gateway_list_http": list_http,
        "gateway_list_category": list_category,
        "gateway_list_comment_hash_match": list_hash_match,
        "mock_sink_tool_calls": NoopSink.tool_calls,
        "no_artifact_upload_step": True,
    }
    print("MSRC_GATEWAY_READ_RECEIPT " + json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        run()
    except ProbeError as exc:
        print("MSRC_GATEWAY_READ_FAILURE " + exc.category, flush=True)
        sys.exit(1)
    except Exception as exc:
        # Never print exception values: HTTP, Docker, or MCP errors may contain
        # credential-bearing headers or the private alert response.
        print("MSRC_GATEWAY_READ_FAILURE unexpected_" + type(exc).__name__ +
              "_at_" + CURRENT_STAGE, flush=True)
        sys.exit(1)
