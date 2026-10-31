# OpenClaw captures for the body-kind tests

`captures.jsonl` holds the requests a real OpenClaw 2026.10.8 sends, as
datrail-project's `openclaw-exec` and `openclaw-gateway` stack jobs run it,
read from the plaintext it wrote to each TLS connection on 2026-10-31:

- the gateway form's three start-up calls, with its default config: the
  update check to `telemetry.openclaw.ai`, the model catalog from
  `catalog.openclaw.ai` and the plugin feed from `clawhub.ai`, all `GET`s
  with no body;
- one `openclaw agent exec` turn against the stack's model stub
  (`tests/openclaw/model_stub.py`): the two `POST /v1/chat/completions`
  requests, before and after its `write` tool call, unchanged apart from
  the host name, the kernel release and install paths, which are replaced
  by the container's (`my-model:8443`, `openclaw-ci`, `/home/node`,
  `/usr/local/lib/node_modules`). `content-length` is dropped, since the
  rewrite changes it.

The model requests carry OpenClaw's own system prompt, tool definitions and
skill descriptions (MIT License, Copyright (c) 2026 OpenClaw Foundation).
