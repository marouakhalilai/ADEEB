# SecureAgent — implementation plan

Full plan with threat model, cost model, diagrams and rationale:
<https://claude.ai/code/artifact/afb6f326-d7f9-4edd-b564-902605f58429>

This file is the in-repo working reference: the decisions that change what you type, and
the exit criteria that decide when a phase is done. Where the two disagree, the artifact
is the narrative and this file is the contract.

## The four corrections

These are the reasons the project is shaped the way it is. Each one, if forgotten, gets
re-introduced as a "simplification" that costs a rewrite.

**1. A Windows service cannot see the desktop or the camera.** Session 0 isolation means
a service cannot enumerate the user's foreground windows, open a webcam through the WinRT
capture stack, invoke Windows Hello, or draw an overlay. Hence two processes: the core
service in Session 0, the broker in the interactive session. This is CLAUDE.md rule 18 and
it is the rule most likely to be violated for convenience.

**2. The camera is contended.** Video calls hold it exclusively, privacy settings revoke
it, lids close. Every policy answers `UnavailableAction` explicitly; every row of the
degraded matrix has a fault-injection test.

**3. An app locker is not a boundary against a local administrator.** They can stop the
service. Only a kernel driver or Microsoft-signed ELAM would change that, and both are
permanent non-goals. The deliverable is tamper-*evidence*: hardened service ACLs, mutual
watchdog, hash-chained audit verified server-side.

**4. Event strings are attacker-controlled.** A window title can contain anything,
including a prompt-injection payload aimed at the analyst layer. Titles are opt-in,
truncated, delimited as evidence, and model output is schema-validated and advisory only.

## Phases and exit criteria

A phase is not done until its exit criterion passes. Do not start the next one.

| Phase | Scope | Exit criterion |
|---|---|---|
| **P0** wk 1 | Skeleton, contracts, CI, licence audit | Green CI on Linux + Windows; `models/provenance.md` verified; signing path confirmed |
| **P1** wk 2 | Data layer, template vault, audit chain | Templates unreadable on a second machine; chain break detected by test |
| **P2** wk 3–4 | Service + broker + ACL'd pipe, foreground hook | Foreground changes logged 24 h at <0.5% idle CPU; broker restart survives kill |
| **P3** wk 5–6 | Verifier ladder: Hello, then local ONNX pipeline | p95 verify <500 ms; FAR/FRR curve published; printed-photo attack rejected |
| **P4** wk 7 | Policy engine, sessions, enforcement, overlay | Every degraded-matrix row has a passing fault-injection test; recovery code works |
| **P5** wk 8–9 | Dashboard, continuous auth, MSI + signing | Clean install→enrol→protect on 3 hardware profiles; 72 h soak clean |
| **P6** wk 10–11 | Control plane on Supabase, signed policy, sync | 7-day offline device syncs cleanly; unsigned policy rejected; erasure receipt verified |
| **P7** wk 12 | Deterministic rule engine, then the Claude analyst | Injection corpus passes; no path from model output to device action without approval |

## Standing non-goals

Kernel drivers. Credential providers. Custom biometric drivers. Antivirus or packet
inspection. Remote shell. Automatic process termination. Any path where model output
reaches an actuator without a human. Any cloud transmission of images or embeddings.

## Blocking gates

| Gate | Blocks | Owner |
|---|---|---|
| Model licence verification (`models/provenance.md`) | P3 | Confirm before calibrating any threshold |
| Code-signing certificate provisioned | P5 | Azure Trusted Signing eligibility must be checked early |
| Biometric-privacy counsel review | Public beta | BIPA / CUBI / GDPR Art. 9 consent and retention |

## Cloud stack

Control plane is NestJS + Prisma on **Supabase Postgres**. Supabase supplies the managed
Postgres, connection pooling, point-in-time recovery on paid tiers, and an auth layer we
can use for the admin dashboard rather than building one.

Two constraints, given what this database holds:

- **No biometric material reaches Supabase.** Embeddings and templates never leave the
  device. The cloud stores events, policies, device registrations and analyst output.
- **Row Level Security is on for every table**, and the service role key stays server-side
  in the NestJS process. It must never reach the Windows client or a browser.

Use the pooled connection string for the API and the direct connection for Prisma
migrations.
