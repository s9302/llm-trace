# llm-trace

Ships every prompt, model reply and tool call made by the AI agents in a homelab
to a self-hosted [Langfuse](https://langfuse.com) instance, over OTLP/HTTP. The
goal is an audit trail: if an agent runs a command on a server, there is a
record of the prompt that led to it, what the model asked for, and what came back.

It's one Python file with no dependencies outside the standard library.

## What it reads

| Source | What's in it |
| --- | --- |
| `~/.claude/projects/**/*.jsonl` | Claude Code transcripts (terminal, web portal and subagent sessions) |
| `~/.local/state/llm-trace/glm.jsonl` | Finished spans written by the portal's GLM agent loop (a self-hosted model, see [llm-modal](https://github.com/s9302/llm-modal)) |

Both are only read, never modified.

## How it maps to traces

- A user prompt becomes the root span of a trace, sent as soon as it appears.
- A model reply is sent once it's complete. Its output lists the tool calls and
  their inputs, so a requested action is on record even if the tool never returns.
- A tool span is sent when its result arrives.

Langfuse v4 stores each exported span as a row and doesn't merge re-exports, so
every span is sent exactly once and only when it's final.

## Reliability

Read positions are byte offsets kept in a state file. They only move forward
after Langfuse accepts a batch, so an outage delays traces but doesn't lose them.
If Langfuse rejects a batch as invalid (HTTP 400/413), the batch is split until the
bad span is isolated, and only that span is dropped.

## Security notes

- The Langfuse keys live in `~/.config/llm-trace/langfuse.json`, outside the repo.
- The client refuses any Langfuse URL that isn't `https://`, since every request
  carries the secret key. (Found by the Semgrep scan in CI.)
- Langfuse itself runs on the tailnet only, and the trace data never leaves the lab.

## Usage

```sh
# ~/.config/llm-trace/langfuse.json
{"url": "https://langfuse.example", "public_key": "pk-lf-...", "secret_key": "sk-lf-..."}

./ship.py                 # run continuously (it runs as a systemd user service)
./ship.py --once          # one pass, including replies still in progress, then exit
./ship.py --backfill      # on first run, also send existing transcripts
./ship.py --backfill --since=2026-11-01T00:00:00Z
```

CI: every push runs gitleaks, Semgrep and Trivy on a self-hosted Forgejo runner
(`.forgejo/workflows/security.yml`).
