#!/usr/bin/env python3
"""Ship LLM activity on this machine to Langfuse over OTLP/HTTP.

Two sources, both read-only and both resumable (byte offsets live in the state file):
  ~/.claude/projects/**/*.jsonl        Claude Code transcripts: terminal, portal and subagent sessions
  ~/.local/state/llm-trace/glm.jsonl   finished spans written by the portal's GLM loop

Langfuse v4 needs each span exported once and complete; a re-export makes a duplicate row. So:
  - a prompt is sent as soon as it appears, as the root span of its trace
  - a model reply is sent once complete; its output lists the tool calls with their inputs, so a
    requested action is on record even if the tool never returns
  - a tool span is sent when its result arrives

Offsets only advance after Langfuse accepts a batch, so an outage delays traces but loses nothing.

--once          do one pass, send replies still in progress, and exit
--backfill      on first run, send existing transcripts too (the default starts at their end)
--since=ISO     with --backfill, skip transcript lines older than this UTC time
"""
import base64
import glob
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

HOME = os.path.expanduser("~")
TRANSCRIPTS = os.path.join(HOME, ".claude/projects/**/*.jsonl")
STATE_DIR = os.environ.get("LLM_TRACE_STATE", os.path.join(HOME, ".local/state/llm-trace"))
STATE_FILE = os.path.join(STATE_DIR, "state.json")
GLM_SPOOL = os.path.join(STATE_DIR, "glm.jsonl")
CONFIG = os.path.join(HOME, ".config/llm-trace/langfuse.json")
POLL_S = 5
RETRY_S = 30
REPLY_IDLE_S = 30             # a reply with no new blocks for this long is treated as complete
TOOL_HUNG_S = 1800            # a pending call this old in a quiet file is recorded as never-returned
MAX_PENDING_TOOLS = 200       # calls that never returned are still on record in their reply
MAX_READ = 4 * 1024 * 1024    # per file per pass
MAX_STRING = 256 * 1024       # per text field; the middle is dropped beyond this
MAX_BATCH = 2 * 1024 * 1024

# Best-effort redaction. Shape rules catch known credential forms; the key=value rules also catch
# secrets with no recognisable shape (incl. all-letter ones) when a secret-ish key names them. It
# still cannot catch a bare secret that nothing around it marks as one.
SECRET_KEY = r"(?:pass(?:word|wd|phrase)?|secret(?:[_-]?key)?|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:[_-]?token|orization)?|token|credentials?)"
REDACTIONS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), "[REDACTED private key]"),
    (re.compile(r"\b(tskey-[A-Za-z0-9-]{10,}|sk-ant-[\w-]{10,}|sk-lf-[\w-]{10,}|sk-[A-Za-z0-9]{20,}|sk_(?:live|test)_[\w-]{10,}|pk_(?:live|test)_[\w-]{10,}|rk_(?:live|test)_[\w-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|glpat-[\w-]{20,}|xox[baprse]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|npm_[A-Za-z0-9]{20,}|dop_v1_[a-f0-9]{32,}|shpat_[a-f0-9]{20,}|SG\.[\w-]{16,}\.[\w-]{16,}|(?:ak|as)-[A-Za-z0-9]{16,}|eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,})"), "[REDACTED token]"),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}"), r"\1 [REDACTED]"),
    # credentials embedded in a URL: scheme://user:PASSWORD@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^/\s@]+(@)"), r"\1[REDACTED]\2"),
    # key = value, value has a digit (the original rule; catches most real secrets inline)
    (re.compile(r"""(?i)([\w-]*""" + SECRET_KEY + r"""[\w-]*["']?\s*[=:]\s*["']?)(?=[^\s"']*\d)[^\s"',;]{8,}"""), r"\1[REDACTED]"),
    # key: "quoted value" of any content (catches all-letter secrets)
    (re.compile(r"""(?i)([\w-]*""" + SECRET_KEY + r"""[\w-]*\s*[=:]\s*)(["'])[^"']{6,}\2"""), r"\1\2[REDACTED]\2"),
    # key = long unquoted single-token value, any content
    (re.compile(r"""(?i)([\w-]*""" + SECRET_KEY + r"""[\w-]*\s*[=:]\s*)[^\s"',;]{12,}"""), r"\1[REDACTED]"),
]


def log(*args):
    print(*args, flush=True)


def hex_id(length, *parts):
    return hashlib.sha256("/".join(str(p) for p in parts).encode()).hexdigest()[:length]


def clean(text):
    for pattern, repl in REDACTIONS:
        text = pattern.sub(repl, text)
    if len(text) > MAX_STRING:
        dropped = len(text) - MAX_STRING
        text = f"{text[:MAX_STRING // 2]}\n... [{dropped} characters not recorded] ...\n{text[-MAX_STRING // 2:]}"
    return text


def block_text(content):
    """Text of a message or tool result, with images replaced by a marker."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return "" if content is None else json.dumps(content)
    parts = []
    for b in content:
        if isinstance(b, str):
            parts.append(b)
        elif b.get("type") == "text":
            parts.append(b.get("text", ""))
        elif b.get("type") != "tool_result":
            parts.append(f"[{b.get('type', 'block')} not recorded]")
    return "\n".join(parts)


def nanos(iso):
    return str(int(datetime.fromisoformat(iso).timestamp() * 1e9))


def otlp_span(s):
    """Convert a finished span record to OTLP JSON, redacting everything that came from a session."""
    def attr(key, value):
        return {"key": key, "value": {"stringValue": clean(value if isinstance(value, str) else json.dumps(value))}}

    attrs = [
        attr("langfuse.trace.name", s["trace_name"]),
        attr("langfuse.environment", s["environment"]),
        attr("langfuse.observation.type", s["type"]),
        {"key": "langfuse.trace.tags", "value": {"arrayValue": {"values": [{"stringValue": t} for t in s.get("tags") or []]}}},
    ]
    if s.get("session"):
        attrs.append(attr("langfuse.session.id", s["session"]))
    for field, key in (("input", "input"), ("output", "output"), ("model", "model.name"), ("usage", "usage_details"),
                       ("level", "level"), ("status", "status_message")):
        if s.get(field) not in (None, ""):
            attrs.append(attr(f"langfuse.observation.{key}", s[field]))
    for key, value in (s.get("metadata") or {}).items():
        if value is not None:
            attrs.append(attr(f"langfuse.observation.metadata.{key}", value))
    span = {"traceId": s["trace_id"], "spanId": s["span_id"], "name": clean(s["name"]), "kind": 1,
            "startTimeUnixNano": nanos(s["start"]), "endTimeUnixNano": nanos(s["end"]), "attributes": attrs}
    if s.get("parent"):
        span["parentSpanId"] = s["parent"]
    return span


class Transcript:
    """Turns transcript lines into finished span records. `s` is this file's persisted state."""

    def __init__(self, path, s):
        self.path, self.s = path, s
        self.subagent = "/subagents/" in path
        s.setdefault("tools", {})  # tool_use_id -> the call, until its result arrives

    def span(self, turn, **fields):
        return {"environment": "claude", "trace_id": turn["trace_id"], "trace_name": turn["name"],
                "session": turn["session"], "tags": turn["tags"], **fields}

    def open_turn(self, d, key, name, text, extra_tag=None):
        tags = [d.get("entrypoint") or "unknown"]
        if self.subagent or d.get("isSidechain"):
            tags.append("subagent")
        if extra_tag:
            tags.append(extra_tag)
        turn = self.s["turn"] = {"trace_id": hex_id(32, "trace", key), "root": hex_id(16, "root", key), "name": name,
                                 "session": d.get("sessionId"), "tags": tags}
        ts = d.get("timestamp")
        out = [self.span(turn, span_id=turn["root"], name=name, type="span", start=ts, end=ts, input=text,
                         metadata={"cwd": d.get("cwd"), "entrypoint": d.get("entrypoint"), "version": d.get("version")})]
        return out + self.emit_shape(turn, ts)

    def turn(self, d):
        """Current turn, opening a placeholder for a session that was already mid-turn."""
        if self.s.get("turn"):
            return self.s["turn"], []
        out = self.open_turn(d, f"joined/{self.path}", "claude: (joined mid-turn)", None)
        return self.s["turn"], out

    def line(self, d):
        kind = d.get("type")
        if kind == "user":
            return self.user(d)
        if kind == "assistant":
            return self.assistant(d)
        if kind == "attachment" and (d.get("attachment") or {}).get("type") == "queued_command":
            return self.note(d, "queued prompt", d["attachment"].get("prompt") or d.get("rendered"))
        if kind == "api-request-shape":  # the system prompt + tool definitions in effect
            return self.shape(d)
        if kind == "system":  # harness notices (safeguards, mode changes, errors)
            text = d.get("content")
            return self.note(d, f"system: {d.get('subtype') or 'notice'}", text) if isinstance(text, str) and text.strip() else []
        return []

    def shape(self, d):
        """Stash the system prompt + tool definitions; emit_shape ships it on the next turn opened."""
        h = d.get("shapeHash")
        if not h:
            return []
        sh = d.get("shape") or {}
        sys_text = "\n\n".join(b.get("text", "") for b in sh.get("system") or [] if isinstance(b, dict))
        tools = sh.get("tools") or []
        names = [t.get("name") or (t.get("function") or {}).get("name") or "?" for t in tools]
        self.s["pending_shape"] = {"hash": h, "system": sys_text, "names": names, "defs": tools}
        return []

    def emit_shape(self, turn, ts):
        """Ship the stashed prompt/tools once per distinct shape, parented to the turn it precedes."""
        shp = self.s.pop("pending_shape", None)
        if not shp or shp["hash"] == self.s.get("shape_hash"):
            return []
        self.s["shape_hash"] = shp["hash"]
        return [self.span(turn, span_id=hex_id(16, "shape", turn["root"], shp["hash"]), parent=turn["root"],
                          name=f"system prompt + {len(shp['names'])} tools", type="event", start=ts, end=ts,
                          input=shp["system"], output=json.dumps(shp["defs"]),
                          metadata={"tools": ", ".join(shp["names"]), "tool_count": len(shp["names"]), "shape_hash": shp["hash"]})]

    def note(self, d, name, text):
        turn, out = self.turn(d)
        ts = d.get("timestamp")
        out.append(self.span(turn, span_id=hex_id(16, "note", d.get("uuid")), parent=turn["root"], name=name, type="event", start=ts, end=ts, input=text))
        return out

    def user(self, d):
        out = self.flush_reply()
        content = (d.get("message") or {}).get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    out += self.tool_result(d, b)
        text = block_text(content)
        if not text.strip():
            return out
        if d.get("isMeta"):
            return out + self.note(d, "injected context", text)
        if d.get("isCompactSummary"):
            return out + self.note(d, "compaction summary", text)
        origin = d["origin"].get("kind") if isinstance(d.get("origin"), dict) else None
        prefix = "claude subagent" if self.subagent or d.get("isSidechain") else "claude"
        name = f"{prefix}: {' '.join(text.split())[:70]}"
        return out + self.open_turn(d, d.get("uuid"), name, text, origin if origin != "human" else None)

    def sweep_tools(self, now, finish):
        """Record a result span for calls that never returned: a killed/hung tool, or session end.
        Only fires in a quiet file (no new lines) or on --once, so a still-running tool is left alone."""
        out, tools, closed = [], self.s.get("tools", {}), self.s.setdefault("closed", [])
        for use_id in list(tools):
            call = tools[use_id]
            if not finish and now - call.get("seen", now) < TOOL_HUNG_S:
                continue
            tools.pop(use_id)
            out.append(self.span(call["turn"], span_id=hex_id(16, "tool", use_id), parent=call["parent"],
                                 name=f"tool: {call['name']}", type="tool", start=call["start"], end=call["start"],
                                 input=call["input"], level="ERROR", metadata={"unresolved": True},
                                 output="[no tool result recorded — the call did not return (killed, hung, or the session ended)]"))
            closed.append(use_id)
        del closed[:-500]  # remember recent closures so a late result is not shipped twice
        return out

    def tool_result(self, d, b):
        ts, use_id = d.get("timestamp"), b.get("tool_use_id")
        closed = self.s.get("closed")
        if closed and use_id in closed:  # already recorded as unresolved; don't duplicate the span
            closed.remove(use_id)
            return []
        call = self.s["tools"].pop(use_id, None)
        if call:
            turn, out = call["turn"], []
        else:
            turn, out = self.turn(d)
            call = {"name": "(call not recorded)", "parent": turn["root"], "start": ts, "input": None}
        out.append(self.span(turn, span_id=hex_id(16, "tool", use_id), parent=call["parent"], name=f"tool: {call['name']}", type="tool",
                             start=call["start"], end=ts, input=call["input"], output=block_text(b.get("content")),
                             level="ERROR" if b.get("is_error") else None))
        return out

    def assistant(self, d):
        m = d.get("message") or {}
        ts = d.get("timestamp")
        mid = m.get("id") or d.get("uuid")
        reply = self.s.get("reply")
        out = []
        if reply and reply["id"] != mid:
            out += self.flush_reply()
            reply = None
        if not reply:
            turn, out2 = self.turn(d)
            out += out2
            part = self.s.get("last_part", 0) + 1 if self.s.get("last_reply") == mid else 0
            reply = self.s["reply"] = {"id": mid, "part": part, "turn": turn, "start": ts, "text": "", "thinking": "", "calls": []}
        for b in m.get("content") or []:
            t = b.get("type")
            if t == "text":
                reply["text"] += b.get("text", "")
            elif t == "thinking":
                reply["thinking"] += b.get("thinking", "")
            elif t == "tool_use":
                reply["calls"].append({"name": b.get("name"), "input": b.get("input")})
                tools = self.s["tools"]
                tools[b.get("id")] = {"turn": reply["turn"], "name": b.get("name"), "input": b.get("input"), "start": ts,
                                      "seen": time.time(), "parent": hex_id(16, "gen", mid, reply["part"])}
                while len(tools) > MAX_PENDING_TOOLS:
                    tools.pop(next(iter(tools)))
        u = m.get("usage") or {}
        reply.update(end=ts, model=m.get("model"), stop=m.get("stop_reason"), seen=time.time(),
                     usage={"input": u.get("input_tokens", 0), "output": u.get("output_tokens", 0),
                            "cache_read": u.get("cache_read_input_tokens", 0), "cache_creation": u.get("cache_creation_input_tokens", 0)})
        return out

    def flush_reply(self):
        reply = self.s.pop("reply", None)
        if not reply:
            return []
        self.s["last_reply"], self.s["last_part"] = reply["id"], reply["part"]
        output = {"text": reply["text"]}
        if reply["thinking"]:
            output["thinking"] = reply["thinking"]
        if reply["calls"]:
            output["tool_calls"] = reply["calls"]
        return [self.span(reply["turn"], span_id=hex_id(16, "gen", reply["id"], reply["part"]), parent=reply["turn"]["root"], name="claude",
                          type="generation", start=reply["start"], end=reply["end"], model=reply["model"], output=output, usage=reply["usage"],
                          metadata={"stop_reason": reply["stop"]})]


class Shipper:
    def __init__(self, cfg):
        # The URL comes from our own config file, but every request carries the
        # Langfuse secret key, so refuse anything that isn't HTTPS (no http://,
        # no file://).
        if urllib.parse.urlsplit(cfg["url"]).scheme != "https":
            raise ValueError("Langfuse url must be https://")
        self.url = cfg["url"].rstrip("/") + "/api/public/otel/v1/traces"
        self.auth = "Basic " + base64.b64encode(f"{cfg['public_key']}:{cfg['secret_key']}".encode()).decode()

    def post(self, spans):
        """Send one batch. Raises if it should be retried; only drops what Langfuse says is invalid."""
        body = {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "llm-trace"}}]},
                                   "scopeSpans": [{"scope": {"name": "llm-trace"}, "spans": spans}]}]}
        req = urllib.request.Request(self.url, json.dumps(body).encode(), {
            "content-type": "application/json", "authorization": self.auth, "x-langfuse-ingestion-version": "4"})
        try:
            # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected  (scheme checked in __init__)
            with urllib.request.urlopen(req, timeout=60) as r:
                result = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (400, 413):
                raise
            if len(spans) > 1:
                mid = len(spans) // 2
                self.post(spans[:mid])
                self.post(spans[mid:])
            else:
                log("REJECTED span", spans[0]["name"][:80], e.code, e.read()[:300])
            return
        rejected = (result.get("partialSuccess") or {}).get("rejectedSpans")
        if rejected:
            log("REJECTED", rejected, "spans:", str(result["partialSuccess"].get("errorMessage"))[:300])

    def send(self, records):
        batch, size = [], 0
        for record in records:
            span = otlp_span(record)
            n = len(json.dumps(span))
            if batch and size + n > MAX_BATCH:
                self.post(batch)
                batch, size = [], 0
            batch.append(span)
            size += n
        if batch:
            self.post(batch)


def read_lines(path, offset):
    """Complete lines after offset, and the offset following the last of them."""
    with open(path, "rb") as f:
        f.seek(offset)
        data = f.read(MAX_READ)
    end = data.rfind(b"\n")
    if end < 0:
        if len(data) == MAX_READ:  # a single line larger than the read window: skip past it
            log("skipped oversized line in", path)
            return [], offset + len(data)
        return [], offset
    return data[:end].split(b"\n"), offset + end + 1


def load_state(backfill, since):
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        pass
    files = {}
    if not backfill:
        for p in glob.glob(TRANSCRIPTS, recursive=True):
            files[p] = {"offset": os.path.getsize(p)}
    return {"files": files, "since": since}


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def ship_file(shipper, state, path, is_transcript, finish):
    """Ship one pass of a file. Returns True if it may have more to read."""
    s = state["files"].setdefault(path, {"offset": 0})
    size = os.path.getsize(path)
    if size < s["offset"]:
        log("file shrank, restarting from its beginning:", path)
        s["offset"] = 0
    # Work on a copy: state only moves on once Langfuse has the spans.
    work = json.loads(json.dumps(s))
    lines, offset = read_lines(path, work["offset"]) if size > work["offset"] else ([], work["offset"])
    records = []
    since = state.get("since")
    transcript = Transcript(path, work) if is_transcript else None
    for raw in lines:
        try:
            d = json.loads(raw)
        except ValueError:
            log("skipped unparseable line in", path)
            continue
        if not is_transcript:
            records.append(d)
        elif not (since and d.get("timestamp") and d["timestamp"] < since):
            records += transcript.line(d)
    reply = work.get("reply")
    if transcript and reply and (finish or time.time() - reply["seen"] > REPLY_IDLE_S):
        records += transcript.flush_reply()
    if transcript and (finish or not lines):  # quiet file: record any calls that never returned
        records += transcript.sweep_tools(time.time(), finish)
    if offset == s["offset"] and not records:
        return False
    shipper.send(records)
    work["offset"] = offset
    state["files"][path] = work
    save_state(state)
    if records:
        log(f"sent {len(records)} spans from {os.path.basename(path)}")
    return offset != s["offset"] and bool(lines)


def one_pass(shipper, state, finish):
    busy = False
    for path in sorted(glob.glob(TRANSCRIPTS, recursive=True)):
        busy |= ship_file(shipper, state, path, True, finish)
    if os.path.exists(GLM_SPOOL):
        busy |= ship_file(shipper, state, GLM_SPOOL, False, finish)
    return busy


def main():
    os.umask(0o077)  # the state file holds pieces of sessions
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    once = "--once" in sys.argv
    since = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--since=")), None)
    with open(CONFIG) as f:
        shipper = Shipper(json.load(f))
    state = load_state("--backfill" in sys.argv, since)
    save_state(state)
    log("shipping to", shipper.url)
    while True:
        try:
            busy = one_pass(shipper, state, once)
        except (OSError, RuntimeError, urllib.error.URLError) as e:
            if once:
                raise
            log("will retry:", e)
            time.sleep(RETRY_S)
            continue
        if not busy:
            if once:
                return
            time.sleep(POLL_S)


if __name__ == "__main__":
    main()
