# Control-plane UI — a proposal for DR-9

**Status: proposal. Nothing here is implemented.** Open
`control-plane-ui-prototype.html` in a browser — it is self-contained, needs no
server, and its data is invented. Most of the vocabulary is real —
`unknown_proxy`, an undecodable `x-rail`, an undeclared destination all come
from RailScan and the gateway. **The 50-point posture gate does not:** no
threshold is defined anywhere yet, and the prototype invents one to have
something to draw. Picking that number is a real decision nobody has made.

## Read this first — the ticket is bigger than it looks

DR-9 has absorbed two cancelled tickets. Daniel's comment on DR-49: *"Merged
into DR-9. Accepting the client credential contract is not separable from
standing in for the control plane — they are one feature, RD-F1, and a feature
must not span two tickets."* So DR-9 now also carries:

- **five routes**, not two — `POST /v1/agents/register`, `GET /v1/tickets`,
  `GET /v1/agents/{agent_id}/status`, `GET /v1/policy-bundle`,
  `POST /v1/denials` (DR-49);
- **the client-credential contract** — accept `none` / `gcp` / `bearer`
  unverified, never log a credential value (DR-49);
- **the Wave-1 keyword scorer, with a manual override**, scoring from
  *RailScan's feature file* rather than from invented numbers (DR-51);
- **running offline in the laptop bundle** with zero control-plane dependency,
  the other three components pointing `RAIL_CENTER_URL` at it unchanged (DR-51).

**This document designs the UI for a third of that.** It is a starting point for
the conversation, not a plan for the ticket.

Two open questions that should be settled before any of it is built:

1. **DR-9's source of truth is the "M2 — RailDash" page**
   (`railxia.atlassian.net/wiki/spaces/SD/pages/15302701#RD-F1`), which this
   document has *not* been checked against — our Confluence auth is currently
   expired. That page is not in `docs/platform-baseline.md` either. The ticket
   says plainly that the page wins where they disagree, and the argument below
   is anchored to an **M1** criterion while the feature lives on an **M2** page.
2. **Lebin asked for something adjacent and has not been answered** (`#rnd-all`,
   2026-08-10): a local dashboard so an open-source-only install, with no Rail
   Center, "can have something to view the RailMon report." The layout below
   drops the interactions view in favour of agents and decisions, which may be
   the opposite of that. Daniel also has a "sync with Lebin on RailDash
   features" queued.

## What DR-9 asks for, and what this covers

DR-9 asks RailDash to **stand in for the control plane** in the offline bundle:
accept a registration on the contract RailScan already speaks (RS-F7), answer
with an agent and a ticket, accept a refusal report on the contract the gateway
speaks (GW-F5), and

> show which agents registered, what they were given, and which calls were
> refused.

`webhook_server.py` today shows a single table of **capture sessions** — session
id, agent string, raw event count, interaction count, start time. It does carry
an agent column, so it is not true that it shows nothing about agents; what it
does not show is a *registered agent* as an object, the ticket that agent was
given, or any refusal at all. Two of the three things DR-9 names are absent, and
the third is a free-text string rather than a registration.

So closing DR-9 is an information-architecture change, not a restyle. That is
the reason for a proposal rather than a patch.

## The one decision worth arguing about

**The headline number should be attribution, not volume.**

Session and event counts only ever increase, so they can never tell you
something is wrong. M1's exit criterion is a captured interaction carrying a
real `agent_id` instead of null — so the largest figure on the page is the share
of interactions actually attributed to an agent, and it turns amber while any
interaction is orphaned.

If you disagree with one thing here, it should be this, because everything else
follows from it.

## Borrowed, deliberately

| Source | What it settles |
| --- | --- |
| [Cloudflare Zero Trust access logs](https://developers.cloudflare.com/cloudflare-one/insights/logs/dashboard-logs/access-authentication-logs/) | Every decision row carries its **block reason**, and the log filters by decision. A gateway that reports "denied" and nothing else cannot be debugged during a demo, so reason is a column rather than something behind a click. |
| [Orca executive risk dashboards](https://orca.security/resources/blog/executive-cloud-risk-dashboards-guide/), [Lansweeper](https://www.lansweeper.com/blog/itam/executive-dashboards-for-it-asset-risk-management-a-complete-guide/) | Summary on one screen, detail on demand. The five posture dimensions sit in a drawer; the table only has to answer "who is below the gate". |

## Two rules the prototype follows

**Status is never colour alone.** Running the `dataviz` palette validator over
the green/amber/red triad put the worst adjacent pair at ΔE 4.5 under
deuteranopia (OKLab ×100, adjacent-pair check).
Two rounds of hex tuning recovered the normal-vision floor but not the
colour-vision one — a traffic-light triad cannot be fixed by choosing better
hues. So every chip pairs its colour with a glyph and a word, and the
unattributed slice of the coverage bar is hatched rather than merely amber.

**Monospace means machine.** Every value a machine produced — `agent_id`,
`host_id`, ticket, destination, timestamp, score — is monospaced; every sentence
a person wrote is not. It costs nothing and separates data from chrome without
reading either.

## Out of scope here

Everything in "the ticket is bigger than it looks" above: the five routes, the
credential contract, the scorer and its override, and offline bundle operation.
The UI is the easy half.

One consequence worth naming: DR-51 requires posture to come from **RailScan's
feature file**. The prototype invents scores with no provenance, so the real
version needs a visible answer to "where did this number come from" that this
design does not yet have.

DR-9's own text applies to the rest: storage, persistence across a restart,
appearance and implementation language are the project's decisions, not
requirements of the ticket.
