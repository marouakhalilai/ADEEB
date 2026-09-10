# SecureAgent

## Product

SecureAgent is a Windows desktop security agent that protects selected applications
using local user authentication, facial verification, application monitoring, and
security policies.

## Primary goal

Build a privacy-first Windows application that allows users to protect individual
applications with local biometric/face authentication.

## The guarantee we actually make

SecureAgent defends against opportunists, casual spoofers and walk-up access to an
unlocked session. It does **not** defend against a local administrator, who can always
stop a service. Against that adversary the goal is tamper-*evidence*, not prevention.
Never write code, copy, or docs that claim otherwise.

## Technology

- C# / .NET 10 (LTS)
- Windows 11
- Windows App SDK / WinUI 3
- SQLite + Entity Framework Core
- OpenCvSharp4 + ONNX Runtime
- Windows APIs / P-Invoke / CsWinRT
- xUnit
- NestJS + Prisma + **Supabase (Postgres)** for the cloud control plane
- Claude API for the advisory analyst layer only

## Architecture

Two client processes, split across the Session 0 boundary. This split is the single
most important structural fact about the codebase.

    windows/
      SecureAgent.Core/           domain + policy engine. No Windows deps. Builds on Linux.
      SecureAgent.Contracts/      IPC + event DTOs, generated from schema/
      SecureAgent.Service/        Session 0, LocalSystem. Policy, templates, keys, audit.
      SecureAgent.Broker/         Interactive session. Hook, camera, Hello, overlay.
      SecureAgent.Face/           IFaceDetector/Embedder/Matcher/Liveness + ONNX impls
      SecureAgent.Infrastructure/ EF Core, vault, outbox, key management
      SecureAgent.Desktop/        WinUI 3 dashboard. No security logic.
      SecureAgent.Tests/          xUnit
      SecureAgent.FaceBench/      FAR/FRR + spoof harness
    cloud/
      apps/api/                   NestJS control plane
      packages/contracts/         TS types generated from schema/
    schema/                       JSON Schema — single source of truth for both sides

## Architecture rules

1. Keep business logic independent of Windows UI.
2. Keep face recognition behind an interface.
3. Never store raw face photographs unless explicitly required for a temporary
   camera operation.
4. Store encrypted biometric templates/embeddings.
5. Never send biometric data to a remote server by default.
6. Face recognition must run locally.
7. Security decisions must be deterministic.
8. AI/LLM functionality must never directly execute privileged actions.
9. The AI layer can recommend actions, but the policy engine must authorize actions.
10. Do not run the main security logic inside the UI process.
11. The Windows agent must continue operating if the UI is closed.
12. Use dependency injection.
13. Use async APIs where appropriate.
14. Use cancellation tokens for long-running operations.
15. Log security events without logging sensitive biometric data.
16. Do not put secrets in source code.
17. All security-sensitive operations must have unit tests.
18. Security logic runs in the Session 0 service. Camera, window hooks, Windows Hello
    and all UI run in the session broker. Never move code across that line to make
    something easier.
19. Camera frames never leave the broker process and never touch disk. The broker
    sends embeddings; the service holds templates.
20. `SecureAgent.Core` has no Windows-specific references and must compile and test
    on Linux. CI enforces this.
21. Every verification failure mode has a defined policy action and a fault-injection
    test. Undefined behaviour is a build failure.
22. Auth session lifetimes use a monotonic clock (`Environment.TickCount64` via
    `ISystemClock`), never wall-clock time.
23. All device-sourced strings (window titles, process names, paths) are untrusted
    input. They are never interpolated into an LLM prompt without delimiting, and
    never treated as instructions.
24. LLM output is schema-validated and advisory. No code path turns a model response
    into a device action without human approval.
25. Log confidence buckets, never scores, embeddings, or images.

## MVP

Implement these features first:

1. User creation
2. Face enrollment
3. Face verification
4. Protected application registration
5. Foreground application detection
6. Application policy evaluation
7. Authentication timeout
8. Allow/block decision
9. Security event logging
10. Desktop UI for managing policies

## MVP protected applications

Initially test with `notepad.exe`, then `calc.exe`, then `chrome.exe`.

Do not implement destructive enforcement. When authentication fails, show a security
overlay and log the event rather than forcefully terminating processes.

## Security

Never:

- upload face data without explicit user consent
- expose biometric embeddings through logs
- hardcode encryption keys
- trust an LLM with unrestricted machine control
- disable Windows security mechanisms
- implement kernel drivers
- implement credential providers
- terminate a user's process automatically

## Development methodology

Implement one feature at a time.

Before changing architecture:

1. Explain the proposed change.
2. Identify affected projects.
3. Implement the smallest safe change.
4. Add tests.
5. Run the build.
6. Run tests.
7. Report failures.

Prefer simple, maintainable implementations over premature abstraction.

## Coding style

Use nullable reference types, dependency injection, explicit interfaces at security
boundaries, small classes, clear names, XML documentation for public security APIs,
and structured logging.

Avoid giant classes, static global state, unnecessary frameworks, hidden background
threads, unsafe code unless absolutely required, and storing sensitive information in
plain text.

## Commands

    dotnet build SecureAgent.slnx
    dotnet test SecureAgent.slnx
    dotnet test --filter Category=Portable     # the Linux-safe subset

## Important

The project is a security product. Correctness and security take priority over speed
of implementation.

See `docs/implementation-plan.md` for the full phased plan, threat model, cost model
and roadmap.
