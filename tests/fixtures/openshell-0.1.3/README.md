# OpenShell 0.1.3 policy output

Recorded verbatim from OpenShell 0.1.3 by datrail-project's *Record OpenShell
fixtures* workflow (`tests/openshell/record-fixtures.sh`, run 40123980582).
Each file is what a user would upload for RailDash's policy import (DR-248).
The sandbox policies the script applies are in that script's `fixtures/`
directory.

| File | What OpenShell printed |
|---|---|
| `base.policy-only.yaml` | `sandbox get --policy-only` for a policy with a read-only REST endpoint, a rules-based one, a plain L4 one and a wildcard on two ports in audit mode |
| `base.policy-only-rev2.yaml` | The same after `policy update --add-endpoint` (revision 2) |
| `base.policy-full.json` | `policy get --full -o json` (carries `active_version`) |
| `base.sandbox-get.json` | `sandbox get -o json` (carries `current_policy_version`, `policy_source`) |
| `provider-pypi.policy-only.yaml` | The base policy plus the rule OpenShell's `pypi` example provider adds (`_provider_fx_pypi`, L4) |
| `provider-github.policy-only.yaml` | The same with the `github` provider, which holds a credential (`_provider_fx_github`: REST, GraphQL and rules) |
| `mcp.policy-only.yaml` | An MCP endpoint with tool rules |
| `allowed-ips.policy-only.yaml` | A host limited by `allowed_ips`, and a hostless `allowed_ips` endpoint |
| `global.policy-only.yaml` | A sandbox's `--policy-only` while a global policy is set: the global one, indistinguishable in YAML |
| `global.sandbox-get.json` | `sandbox get -o json` then: `policy_source: global` |
| `global.policy-get-global.json` | `policy get --global --full -o json` (`scope: global`) |
| `collector-policy.json` | `base.policy-full.json`'s policy as `railmon openshell` posts it (DR-249): railmon's `strip_policy` over the same recorded output |
| `collector-denials.json` | The first poll's denials post: railmon's parser over the base sandbox's recorded `openshell logs --source sandbox` (an L7 `POST` denial, an L4 host no rule names, the metadata address) |
| `missing-sandbox.stderr.txt` | What `--policy-only` prints for a sandbox that doesn't exist (stderr; stdout is empty) |

One value is not verbatim: the `internal.openshell.ai/gateway-token-id`
annotation in the two `sandbox get -o json` files reads `(redacted)`. It
names a token on the throwaway CI gateway, not the token itself, but nothing
here needs it.

The `github` provider was created with a marker credential. The workflow
checks that the marker appears in no output, so none of these files carries
a credential.
