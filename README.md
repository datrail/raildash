# RailDash

RailDash receives DatRail capture events and provides a lightweight session
dashboard. This repository is the Wave 1 baseline split from
`monitor-poc/webhook/`.

RailDash does not run eBPF capture. Deploy the separate `railmon` component to
produce runtime interactions and configure its webhook/output path for the
deployment. The copied PoC collector was removed during the split because it
depended on monorepo-only paths; its original instructions remain in
[`docs/legacy-webhook-poc.md`](docs/legacy-webhook-poc.md).

## Run

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn webhook_server:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000/>. The API contract is in
[`openapi.yaml`](openapi.yaml).

## Current scope

This baseline stores sessions in process memory. Restarting RailDash loses all
data, and it has no authentication, multi-tenant isolation, or posture-model
integration. Persistence and the Wave 1 posture scorer must land before this is
a production dashboard.

## Validate

```bash
pip install -r requirements-dev.txt
make test
```

## License

No standalone license has been selected yet. Resolve this before making the
repository public.
