# ASP v1 acceptance and maintainer handoff

Run the acceptance oracle from a clean Python 3.10+ environment:

```bash
python -m venv /tmp/raildash-asp-v1-venv
/tmp/raildash-asp-v1-venv/bin/pip install .
/tmp/raildash-asp-v1-venv/bin/raildash-asp-acceptance
```

It uses the checked-in redacted RailMon evidence fixture and a temporary
owner-only SQLite database. A passing JSON result proves:

- exact-byte replay is idempotent and aligned;
- a controlled evidence change produces `DRIFT_DETECTED`;
- switching to the changed ASP's alignment version produces `ALIGNED`;
- switching back restores the prior drift result; and
- a rule-pack mismatch produces `COMPARISON_UNAVAILABLE` with
  `CONTRACT_MISMATCH`, never a false clean result.

No evidence values or digests are printed. Pass `--database` only with a new
path beneath a private parent when the acceptance records need to be retained;
the oracle refuses an existing database so it cannot alter operational state.

For a live demonstration, stop RailDash and use `raildash asp load`, `list`,
`lock`, and `switch` against real RailMon evidence, restart with
`raildash serve`, then open the Agent Security Profile alignment panel. The
panel shows the same aligned, drifted, or comparison-unavailable outcomes and
keeps full evidence on the owner-only CLI.

## Published-install gate

The published acceptance leg is complete only after a released RailDash image
or package contains the merged ASP v1 commits. A wheel installs the
`raildash-asp-acceptance` command and its redacted fixture. A container includes
the same module and fixture, so run `python -m raildash.acceptance` inside it.
Then repeat the live flow with RailMon and capture the alignment panel. A
source checkout, passing CI image build, or an older published tag is not
evidence for this gate.
