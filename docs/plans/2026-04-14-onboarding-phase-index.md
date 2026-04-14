# Onboarding Implementation — Phase Index

**Spec:** [2026-04-14-onboarding-design.md](./2026-04-14-onboarding-design.md)
**Total estimated size:** ~6-7 weeks of focused work
**Execution order:** strictly sequential. Each phase produces working, testable software.

---

## Prerequisites

- [ ] `feat/multi-tenant` merged to `main` (provides Identity context foundation — users, orgs, self-managed auth, JWT, session cache). This is a hard blocker for Phase 1.

Verify with: `git log main --grep "multi-tenant" --oneline | head -1` should show the merge commit.

---

## Phases

| # | Name | Stated deliverable | Plan file | Size |
|---|---|---|---|---|
| 1 | Portal foundation | Portal container with login, RBAC (Owner/Engineer/Officer), groups/hosts CRUD (manual add), audit log write path, empty dashboard. Engineer can sign up, invite others, create a group, add a host row manually, verify role gates work. | `2026-04-14-onboarding-phase-1-portal-foundation-plan.md` | ~1.5 wk |
| 2 | Engine enrollment + heartbeat | Engine container skeleton, portal generates signed bundle, engine enrolls via mTLS, heartbeat polling, portal UI shows "Engine X online/offline." No scan jobs yet — just the trust handshake and liveness signal. | `2026-04-14-onboarding-phase-2-engine-enrollment-plan.md` | ~1 wk |
| 3 | Inventory ingest | CSV import (drag/drop → column map → dry-run → commit) + network discovery (CIDR input → engine runs ICMP/TCP-SYN sweep → candidates stream back over engine gateway → user selects rows → add to group). | `2026-04-14-onboarding-phase-3-inventory-ingest-plan.md` | ~1 wk |
| 4 | Credentials + secret push | Profile CRUD UI, engine pubkey endpoint, browser-side encryption of secrets to engine pubkey, portal forwards opaque ciphertext to engine, engine keystore stores AES-256-GCM ciphertext, "test against N hosts" probe. Portal never sees plaintext. | `2026-04-14-onboarding-phase-4-credentials-plan.md` | ~1 wk |
| 5 | Scan jobs + first agentless scan | Job queue on portal, `/engine/jobs/poll` long-poll, `/engine/jobs/{id}/progress` stream, `/engine/jobs/{id}/submit`. Engine wires existing scanner Engine (the agentless Unix wiring already shipped) to pulled jobs. First portal-triggered scan produces findings visible in existing report dashboard. | `2026-04-14-onboarding-phase-5-scan-jobs-plan.md` | ~1 wk |
| 6 | Agent-push + per-host certs | New credential profile type `bootstrap-admin`, agent-push job flow, per-host cert minting by engine at push time, agent binary bootstrap with mTLS client cert, `/agents/register` endpoint on engine, host flips from agentless to agent-mode in UI. | `2026-04-14-onboarding-phase-6-agent-push-plan.md` | ~1 wk |
| 7 | Audit + polish | Full audit log UI (searchable event timeline), error states across all surfaces, 20-minute success-metric instrumentation (timestamps per journey step), end-to-end smoke test reproducing the customer journey. | `2026-04-14-onboarding-phase-7-audit-polish-plan.md` | ~3 days |

---

## Writing cadence

Each phase plan is written **just-in-time** — detailed task-level plan is produced right before that phase begins execution, not in advance. This avoids plan rot: what we learn in Phase 1 informs the Phase 2 plan.

After each phase plan is written, use `superpowers:subagent-driven-development` to execute.

After each phase merges, invoke `superpowers:writing-plans` again with the next phase's scope to produce its plan.

---

## Branch strategy

Each phase gets its own branch off main: `feat/onboarding-phase-N-<slug>`. Merge to main at phase end. Subsequent phase branches are cut from latest main.

The current worktree (`worktree-agentless-followups`) hosts the design spec and phase plans. Implementation happens on phase branches in separate worktrees or on main clones, not here.
