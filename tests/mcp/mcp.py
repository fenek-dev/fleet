"""Minimal MCP stdio client for `fleetctl mcp` (newline-delimited JSON-RPC).

    from mcp import Mcp
    m = Mcp(fleetctl, socket, client="tester")
    m.initialize()
    r = m.call("fleet_list_servers", {})
    r.error, r.code, r.summary, r.untrusted, r.texts

No dependencies beyond the standard library. See tests/mcp/run.py.
"""
import json
import os
import queue
import re
import subprocess
import threading
import time

PROTOCOL = "2025-06-18"


class Result:
    """A `tools/call` result: first text block = summary, rest = untrusted."""

    def __init__(self, raw):
        self.raw = raw
        self.error = bool(raw.get("isError"))
        self.texts = [c.get("text", "") for c in raw.get("content", [])]
        self.code = None
        self.summary = None
        self.untrusted = []
        if self.error:
            t = self.texts[0] if self.texts else ""
            self.code = t.split(":", 1)[0]
        else:
            try:
                self.summary = json.loads(self.texts[0]) if self.texts else None
            except ValueError:
                self.summary = self.texts[0] if self.texts else None
            self.untrusted = self.texts[1:]

    def __repr__(self):
        s = json.dumps(self.raw)
        return f"Result({s[:400]}{'…' if len(s) > 400 else ''})"


class Mcp:
    def __init__(self, fleetctl, socket, client="fleet-mcp-test", prefix=None, env=None):
        e = dict(os.environ)
        if socket is not None:
            e["FLEET_MCP_SOCKET"] = socket
        else:
            e.pop("FLEET_MCP_SOCKET", None)
        e.update(env or {})
        self.client = client
        self.p = subprocess.Popen(
            (prefix or []) + [fleetctl, "mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=e,
            text=True,
            bufsize=1,
        )
        self.q = queue.Queue()
        self.stderr = []
        self.next_id = 1
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._read_err, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                self.q.put(json.loads(line))
            except ValueError:
                self.q.put({"_raw": line})
        self.q.put(None)

    def _read_err(self):
        for line in self.p.stderr:
            self.stderr.append(line.rstrip())

    def send(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def request(self, method, params=None, timeout=30):
        rid = self.next_id
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        deadline = time.time() + timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                raise TimeoutError(f"{method} timed out after {timeout}s")
            try:
                m = self.q.get(timeout=left)
            except queue.Empty:
                raise TimeoutError(f"{method} timed out after {timeout}s")
            if m is None:
                raise EOFError(f"fleetctl exited ({self.p.poll()}): {self.stderr[-5:]}")
            if m.get("id") == rid:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m["result"]
            # notifications / server requests are ignored

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)

    def initialize(self):
        r = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": self.client, "version": "1.0"},
            },
        )
        self.notify("notifications/initialized")
        self.info = r
        return r

    def tools(self):
        return self.request("tools/list", {})["tools"]

    def call(self, name, args=None, timeout=60):
        return Result(self.request("tools/call", {"name": name, "arguments": args or {}}, timeout))

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


MARKER = re.compile(r'^<untrusted_content nonce="([0-9a-f]{32})"[^>]*>.*</untrusted_content nonce="\1">\s*$', re.S)


def is_marked(block):
    """True when a whole block is one untrusted_content element."""
    return bool(MARKER.match(block))
