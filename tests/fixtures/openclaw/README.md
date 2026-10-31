# OpenClaw captures for the body-kind tests

`captures.jsonl` holds the requests a real OpenClaw 2026.10.8 sends, run
outside CI with the config datrail-project's `openclaw-exec` and
`openclaw-gateway` stack jobs use, read from the plaintext it wrote to each
TLS connection on 2026-10-31:

- the gateway form's three start-up calls, which that config leaves on: the
  update check to `telemetry.openclaw.ai`, the model catalog from
  `catalog.openclaw.ai` and the plugin feed from `clawhub.ai`, all `GET`s
  with no body;
- one `openclaw agent exec` turn against the stack's model stub
  (datrail-project's `tests/openclaw/model_stub.py`): the two `POST
  /v1/chat/completions` requests, before and after its `write` tool call.
  They are unchanged apart from stand-ins for values of the machine that
  captured them: the model host (`my-model:8443`, as in the stack), the host
  name (`openclaw-ci`), the kernel release (`6.8.0`) and the install and
  work paths (`/usr/local/lib/node_modules`, `/home/node`). `content-length`
  is dropped, since the rewrite changes it.

Timestamps are approximate (within a minute); nothing reads them. The model
requests carry OpenClaw's own system prompt, tool definitions and skill
descriptions, under its license below.

## OpenClaw license

    MIT License

    Copyright (c) 2026 OpenClaw Foundation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
