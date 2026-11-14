# Changelog

Notable changes to RailDash, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Each date is the
tagged commit's date.

Each PR adds its line under `## Unreleased`.

## Unreleased

Nothing yet.

## [v0.2.0-rc.17] - 2026-11-10

### Changed

- Drift compares values in the one ASP spelling Rail Center reads, so a spelling or list-order difference alone (`root` and `0`, a default port, a `CAP_` prefix, `v24` and `24`) is no longer drift ([#124](https://github.com/datrail/raildash/pull/124)).
- Each attribute is read through RailMon's `asp_normalize`, and a v2 bundle whose scopes disagree is refused ([#125](https://github.com/datrail/raildash/pull/125)).
- A tag's GitHub Release notes open with the annotated tag's message ([#126](https://github.com/datrail/raildash/pull/126)).

## [v0.2.0-rc.16] - 2026-11-03

### Added

- An imported API spec marks an operation that takes files or content, so its requests are uploads ([#119](https://github.com/datrail/raildash/pull/119)).

### Changed

- The README covers This is parameters, Narrow uploads and bytes by body kind ([#118](https://github.com/datrail/raildash/pull/118)).
- The body-kind docstring says step 3 reads the imported spec ([#120](https://github.com/datrail/raildash/pull/120)).
- The body-kind table test includes real OpenClaw captures ([#121](https://github.com/datrail/raildash/pull/121)).
- The container release workflow creates the tag's GitHub Release ([#123](https://github.com/datrail/raildash/pull/123)).

### Fixed

- The guardrail's parsers load without the SQLite store ([#122](https://github.com/datrail/raildash/pull/122)).

## [v0.2.0-rc.15] - 2026-10-31

### Added

- Body kinds tell a REST upload from a POST that passes parameters ([#112](https://github.com/datrail/raildash/pull/112)).
- The uploads rule and its proposal read body kinds ([#113](https://github.com/datrail/raildash/pull/113)).
- The drip check; body kinds are on by default ([#114](https://github.com/datrail/raildash/pull/114)).
- An upload row says what each body was, and This is parameters answers it ([#115](https://github.com/datrail/raildash/pull/115)).
- Offer to narrow upload hosts that were only sent parameters ([#116](https://github.com/datrail/raildash/pull/116)).
- Bytes sent per host are split by body kind, with the one-time pass ([#117](https://github.com/datrail/raildash/pull/117)).

## [v0.2.0-rc.14] - 2026-10-29

### Fixed

- An all-lower-case `mkdtemp` name of a family the lists show is folded too ([#111](https://github.com/datrail/raildash/pull/111)).

## [v0.2.0-rc.13] - 2026-10-29

### Added

- Take an OpenShell allow-list RailMon carries (RailMon rule pack 14) and count it on the Egress line ([#110](https://github.com/datrail/raildash/pull/110)).

## [v0.2.0-rc.12] - 2026-10-28

### Changed

- A request OpenShell blocked at L7 doesn't count against the guardrail ([#109](https://github.com/datrail/raildash/pull/109)).

## [v0.2.0-rc.11] - 2026-10-27

### Fixed

- The OpenShell export leaves out loopback and link-local hosts, and rolls back through `policy get`'s JSON ([#108](https://github.com/datrail/raildash/pull/108)).

## [v0.2.0-rc.10] - 2026-10-27

### Added

- Download the guardrail in force as an OpenShell policy ([#107](https://github.com/datrail/raildash/pull/107)).

## [v0.2.0-rc.9] - 2026-10-27

### Added

- List the hosts an OpenShell policy allows beyond the guardrail ([#105](https://github.com/datrail/raildash/pull/105)).

### Fixed

- SQLite temp files and `mkdtemp` directories fold like a uuid ([#106](https://github.com/datrail/raildash/pull/106)).

## [v0.2.0-rc.8] - 2026-10-24

### Added

- Take `railmon openshell`'s policy revisions and denials; Blocked by OpenShell is listed under the Egress line ([#104](https://github.com/datrail/raildash/pull/104)).

## [v0.2.0-rc.7] - 2026-10-24

### Added

- Import an OpenShell sandbox's policy, show it on the Egress line and seed the proposal from it ([#103](https://github.com/datrail/raildash/pull/103)).

## [v0.2.0-rc.6] - 2026-10-24

### Fixed

- The proposal for an agent OpenShell contains allows OpenShell's DNS ([#102](https://github.com/datrail/raildash/pull/102)).

## [v0.2.0-rc.5] - 2026-10-23

### Fixed

- Inspect evidence stays open across the LIVE refresh ([#101](https://github.com/datrail/raildash/pull/101)).

## [v0.2.0-rc.4] - 2026-10-23

### Added

- Golden tests on real Claude Code and Codex captures; Codex code mode's tool calls are read ([#100](https://github.com/datrail/raildash/pull/100)).

## [v0.2.0-rc.3] - 2026-10-23

### Changed

- The UI and API text name RailMon's file probe, not filesnoop ([#99](https://github.com/datrail/raildash/pull/99)).

### Fixed

- A keyed v1 bundle in a multi-agent sandbox is filed under its agent key ([#98](https://github.com/datrail/raildash/pull/98)).

## [v0.2.0-rc.2] - 2026-10-23

### Changed

- The README documents the classifier's model settings and how to downgrade ([#95](https://github.com/datrail/raildash/pull/95)).
- The `egress_containment` rule judges a multi-agent sandbox on its sandbox-scoped level ([#96](https://github.com/datrail/raildash/pull/96)).
- RailDash refuses an unkeyed v1 bundle for a sandbox with keyed v2 history ([#97](https://github.com/datrail/raildash/pull/97)).

## [v0.2.0-rc.1] - 2026-10-22

### Added

- ASP v1 contracts and a deterministic comparator ([#18](https://github.com/datrail/raildash/pull/18)).
- Local ASP custody and alignment workflows ([#21](https://github.com/datrail/raildash/pull/21)), with ASP alignment and drift alerts in the UI ([#22](https://github.com/datrail/raildash/pull/22)).
- ASP write routes and UI, so the CLI is optional ([#28](https://github.com/datrail/raildash/pull/28)).
- Consume multi-agent runtime attribution ([#25](https://github.com/datrail/raildash/pull/25)).
- Consume evidence bundle v2 ([#30](https://github.com/datrail/raildash/pull/30), [#31](https://github.com/datrail/raildash/pull/31)), index agents and queue unattributed interactions separately ([#33](https://github.com/datrail/raildash/pull/33)), and lock and compare multi-agent baselines ([#37](https://github.com/datrail/raildash/pull/37)).
- The observed profile and capture drift show uploaded content kinds ([#35](https://github.com/datrail/raildash/pull/35)), bytes sent per destination host ([#40](https://github.com/datrail/raildash/pull/40)) and the files tool calls read or write ([#41](https://github.com/datrail/raildash/pull/41)).
- List received ASPs, lock any as baseline, and download their exact bytes ([#45](https://github.com/datrail/raildash/pull/45)).
- Kernel-observed file access shows beside the asked files, with drift by path ([#46](https://github.com/datrail/raildash/pull/46)).
- v2 attributes that declare a window are compared as window lists ([#49](https://github.com/datrail/raildash/pull/49)).
- The Data Guardrail: its contract and pure evaluator ([#55](https://github.com/datrail/raildash/pull/55)); collector heartbeats and captures marked as sent with the local token ([#56](https://github.com/datrail/raildash/pull/56)); a refused authenticated capture batch is recorded and keeps the request rules Unverified ([#57](https://github.com/datrail/raildash/pull/57)); guardrail versions and rows checked from both ingest paths ([#58](https://github.com/datrail/raildash/pull/58)); its state and every custody action over HTTP ([#59](https://github.com/datrail/raildash/pull/59)); and the panel beside the alignment panel ([#60](https://github.com/datrail/raildash/pull/60)).
- Data actions: tool schemas read from captured traffic ([#68](https://github.com/datrail/raildash/pull/68)); tools classified into data actions from their schemas ([#69](https://github.com/datrail/raildash/pull/69)); each tool call recorded as a data-action row ([#70](https://github.com/datrail/raildash/pull/70)); the observed profile shows each tool's data actions ([#71](https://github.com/datrail/raildash/pull/71)); MCP calls lined up with their declared server ([#72](https://github.com/datrail/raildash/pull/72)); the `data_actions` guardrail rule in contract v2 ([#73](https://github.com/datrail/raildash/pull/73)); the proposal includes data actions and v1 agents are offered them ([#74](https://github.com/datrail/raildash/pull/74)); a tool its endpoint never offered is a violation, judged after a delay ([#75](https://github.com/datrail/raildash/pull/75)); the panel says why a tool is classified as it is and lets the user override its actions ([#76](https://github.com/datrail/raildash/pull/76)); and an opt-in classifier step that asks the user's own model ([#77](https://github.com/datrail/raildash/pull/77)).
- The Egress line, and a guardrail that can require containment ([#80](https://github.com/datrail/raildash/pull/80)).
- Seed the proposal with one shown glob for Python bytecode caches ([#65](https://github.com/datrail/raildash/pull/65)).
- The model step can answer that a tool takes no data action, and the tool stays unclassified ([#86](https://github.com/datrail/raildash/pull/86)).
- Golden tests on real MCP captures from the stack ([#78](https://github.com/datrail/raildash/pull/78)).

### Changed

- Validate evidence bundles against RailMon's schema, not a hand copy ([#27](https://github.com/datrail/raildash/pull/27)).
- Bound ASP payloads and results ([#20](https://github.com/datrail/raildash/pull/20)).
- Leave the value of an attribute RailMon publishes as dynamic out of drift ([#52](https://github.com/datrail/raildash/pull/52)); CI checks the vendored `attribute-groups.json` against RailMon's ([#53](https://github.com/datrail/raildash/pull/53)).
- A re-sent unchanged ASP keeps the guardrail's evidence fresh ([#61](https://github.com/datrail/raildash/pull/61)).
- Show each guardrail rule as its own rows say, not its liveness ([#63](https://github.com/datrail/raildash/pull/63)).
- Allow a rule's rows in one version, not one click and one version per row ([#66](https://github.com/datrail/raildash/pull/66)).
- Cap the Observed security profile's lists at 20, with Show all ([#64](https://github.com/datrail/raildash/pull/64)); page the interaction log at 25 rows and give kernel-observed files the panel's width ([#67](https://github.com/datrail/raildash/pull/67)).
- Stack the bytes-per-host count under the host name ([#47](https://github.com/datrail/raildash/pull/47)).
- Say why the Observed security profile is empty instead of reading as broken ([#51](https://github.com/datrail/raildash/pull/51)).
- `destructiveHint` adds no action, mode arguments count, and the verb table gains missing verbs ([#83](https://github.com/datrail/raildash/pull/83)); write, save, put, push and apply are also update, since they overwrite ([#84](https://github.com/datrail/raildash/pull/84)); a boolean flag named for a delete adds delete, unless the tool's name only reads ([#90](https://github.com/datrail/raildash/pull/90)).
- The model prompt counts content entered into a page, form or dialog as upload ([#87](https://github.com/datrail/raildash/pull/87)).
- A read only a tool's description gives is weak, and a proposal doesn't allow a called tool's weak read alone ([#88](https://github.com/datrail/raildash/pull/88)).
- A contained agent's Egress line says it should not reach outside hosts ([#91](https://github.com/datrail/raildash/pull/91)).
- The interaction log counts a streamed reply's tool calls, and Gemini's index-less calls stay apart ([#94](https://github.com/datrail/raildash/pull/94)).
- Docs: point a new user at datrail-project first ([#50](https://github.com/datrail/raildash/pull/50)); the README's opening says what RailDash does today ([#81](https://github.com/datrail/raildash/pull/81)); the README says the guardrail judges authenticated captures ([#62](https://github.com/datrail/raildash/pull/62)); correct the public docs and drop internal references ([#44](https://github.com/datrail/raildash/pull/44)); fix documentation drift and remove duplicate code, no behaviour change ([#54](https://github.com/datrail/raildash/pull/54)); a docstring no longer says an over-bound request arrives cut ([#79](https://github.com/datrail/raildash/pull/79)); name Rail Center's register route, not its removed evidence-bundles route ([#89](https://github.com/datrail/raildash/pull/89)); the maintainer pairing handoff runbook ([#29](https://github.com/datrail/raildash/pull/29)).
- CI: ASP v1 acceptance harness ([#23](https://github.com/datrail/raildash/pull/23)); default ASP database launch check ([#24](https://github.com/datrail/raildash/pull/24)); recurring ASP browser regression ([#26](https://github.com/datrail/raildash/pull/26)); smoke test of the built image ([#34](https://github.com/datrail/raildash/pull/34)); run on `ubuntu-26.04` by name ([#36](https://github.com/datrail/raildash/pull/36)); the RailMon schema drift check fails instead of skipping ([#43](https://github.com/datrail/raildash/pull/43)); workflow actions on their Node 24 majors ([#48](https://github.com/datrail/raildash/pull/48)).
- The stack scripts move out to datrail-project ([#17](https://github.com/datrail/raildash/pull/17)).

### Fixed

- Preserve container identity qualifier drift ([#19](https://github.com/datrail/raildash/pull/19)).
- Re-vendor the v2 schema so RailDash accepts `MULTI_AGENT_SCOPE_UNRESOLVED` ([#32](https://github.com/datrail/raildash/pull/32)).
- Keep the local write token stable across restarts ([#42](https://github.com/datrail/raildash/pull/42)).
- A call made in the first second of a guardrail version is judged ([#82](https://github.com/datrail/raildash/pull/82)).
- A v1 bundle's window lists are compared as windows, so a quieter or recounted re-scan is not drift ([#85](https://github.com/datrail/raildash/pull/85)).
- A file list capped only by reads still verifies Saved files ([#93](https://github.com/datrail/raildash/pull/93)).
- A uuid-named file and a capped file list are not drift, and the guardrail allows the uuid glob ([#92](https://github.com/datrail/raildash/pull/92)).

## [v0.1.0] - 2026-09-02

The initial public release (commit `efbd68e`, 2026-09-01), with the
install guide on top. The work merged before it (PRs #2 to #15) is squashed
into that one commit.

### Added

- `INSTALL.md`, the canonical install guide, linked from the README ([#16](https://github.com/datrail/raildash/pull/16)).

[v0.2.0-rc.17]: https://github.com/datrail/raildash/compare/v0.2.0-rc.16...v0.2.0-rc.17
[v0.2.0-rc.16]: https://github.com/datrail/raildash/compare/v0.2.0-rc.15...v0.2.0-rc.16
[v0.2.0-rc.15]: https://github.com/datrail/raildash/compare/v0.2.0-rc.14...v0.2.0-rc.15
[v0.2.0-rc.14]: https://github.com/datrail/raildash/compare/v0.2.0-rc.13...v0.2.0-rc.14
[v0.2.0-rc.13]: https://github.com/datrail/raildash/compare/v0.2.0-rc.12...v0.2.0-rc.13
[v0.2.0-rc.12]: https://github.com/datrail/raildash/compare/v0.2.0-rc.11...v0.2.0-rc.12
[v0.2.0-rc.11]: https://github.com/datrail/raildash/compare/v0.2.0-rc.10...v0.2.0-rc.11
[v0.2.0-rc.10]: https://github.com/datrail/raildash/compare/v0.2.0-rc.9...v0.2.0-rc.10
[v0.2.0-rc.9]: https://github.com/datrail/raildash/compare/v0.2.0-rc.8...v0.2.0-rc.9
[v0.2.0-rc.8]: https://github.com/datrail/raildash/compare/v0.2.0-rc.7...v0.2.0-rc.8
[v0.2.0-rc.7]: https://github.com/datrail/raildash/compare/v0.2.0-rc.6...v0.2.0-rc.7
[v0.2.0-rc.6]: https://github.com/datrail/raildash/compare/v0.2.0-rc.5...v0.2.0-rc.6
[v0.2.0-rc.5]: https://github.com/datrail/raildash/compare/v0.2.0-rc.4...v0.2.0-rc.5
[v0.2.0-rc.4]: https://github.com/datrail/raildash/compare/v0.2.0-rc.3...v0.2.0-rc.4
[v0.2.0-rc.3]: https://github.com/datrail/raildash/compare/v0.2.0-rc.2...v0.2.0-rc.3
[v0.2.0-rc.2]: https://github.com/datrail/raildash/compare/v0.2.0-rc.1...v0.2.0-rc.2
[v0.2.0-rc.1]: https://github.com/datrail/raildash/compare/v0.1.0...v0.2.0-rc.1
[v0.1.0]: https://github.com/datrail/raildash/releases/tag/v0.1.0
