# Running SecureAgent locally

This walks through getting a working protected application on your own machine. It takes
about five minutes.

## What works today

The full loop runs: **foreground detection → IPC → policy evaluation → Windows Hello →
allow/deny → hash-chained audit record.**

| Working | Not built yet |
|---|---|
| Foreground application detection | Local face recognition (P3, licence-gated) |
| Named-pipe IPC with an explicit DACL | Continuous presence checks |
| Deterministic policy engine + sessions | Encrypted template vault |
| Windows Hello verification | WinUI dashboard |
| Full-screen enforcement overlay | Windows service installation |
| Hash-chained, verifiable audit log | Cloud sync |
| CLI to configure everything | Installer |

Verification is **Windows Hello only** right now. That is a deliberate ordering choice, not
a shortcut: Hello needs no model licences and no downloads, it brings Microsoft's
anti-spoofing and IR hardware support, and no biometric data ever reaches this process. The
local ONNX engine slots in behind the same `IIdentityVerifier` interface once
`models/provenance.md` clears its licence review.

## Prerequisites

- Windows 11, .NET 10 SDK (see [development-setup.md](development-setup.md))
- **Windows Hello configured** — Settings → Accounts → Sign-in options → Face or Fingerprint.
  Without it the verifier reports itself unavailable and the policy's fallback applies.

## 1. Build

    cd C:\Users\Microsoft\Documents\windows_security
    dotnet build SecureAgent.slnx -c Release

## 2. Set the two executable paths

The broker targets a versioned Windows TFM, so its output folder differs from the service's.

    $svc = ".\windows\SecureAgent.Service\bin\Release\net10.0-windows\SecureAgent.Service.exe"
    $brk = ".\windows\SecureAgent.Broker\bin\Release\net10.0-windows10.0.26100.0\SecureAgent.Broker.exe"

## 3. Create your identity

`--me` binds the identity to your Windows account. Windows Hello attests the account owner
and returns no identity of its own, so without this binding the Hello rung has nothing to
map a success onto and will report itself unavailable.

    & $svc add-user "Adeeb" --me
    & $svc users

## 4. Protect an application

Use Notepad first, not Chrome. If something is wrong you want it to be wrong somewhere
harmless.

    & $svc protect notepad.exe --user <the-id-from-step-3> --assurance HelloOrIr --ttl 300

Options: `--assurance Any|Biometric|HelloOrIr`, `--ttl <seconds>`,
`--on-fail Overlay|Minimize|LockApp|LockWorkstation`.

Check it landed:

    & $svc policies
    & $svc status

## 5. Start both processes

Two processes, because a Session 0 service cannot see the desktop or the camera. Run each in
its own terminal so you can watch the logs.

Terminal 1 — the service:

    & $svc

Terminal 2 — the broker:

    & $brk

Wait for `IPC listening on pipe SecureAgent.Ipc` in the first and `Connected to the
SecureAgent service` in the second.

## 6. Try it

Open Notepad. You should see, in the service log:

    notepad.exe activated: VerificationRequired (policy notepad.exe, matched by FileName)

and in the broker log:

    Verifier ladder: 1 rung(s), strongest WindowsHello
    Verification requested for assurance Biometric; using WindowsHello

A Windows Hello prompt appears. Pass it and Notepad is allowed, and the session lasts for
your `--ttl`, so reopening Notepad within that window does not prompt again. Fail or cancel
it and the overlay appears.

## 7. Inspect the audit trail

    & $svc events 20
    & $svc verify-chain

`verify-chain` recomputes every record's hash and checks continuity. Deleting or editing a
row breaks it, which is the point: the product cannot stop an administrator tampering with
the log, but it can make tampering visible.

## Behaviour worth knowing

**Cancelling the Hello prompt is not treated as an intruder.** It records
`VerificationInconclusive` and leaves the application alone. An empty chair is not an
attacker, and locking people out on an unanswered prompt is how this class of product gets
uninstalled.

**No Hello, or Hello unavailable** falls to the policy's `OnVerifierUnavailable`, which
defaults to allow-and-record with outcome `Degraded`. That is a policy decision you can
change per application; what it must never do is stay silent while claiming protection.

**Nothing is logged for unprotected applications.** Most foreground changes on a real
desktop match no policy, and recording them all would bury the events that matter.

## Limits — read before trusting it

- **Not a defence against a local administrator.** They can stop the service or kill the
  broker. The goal against that adversary is tamper-*evidence*, not prevention.
- **Not installed as a service yet**, so nothing restarts it if it stops.
- **File-name matching is weak.** Copying and renaming a binary defeats it. The CLI refuses
  to create a `HelloOrIr` policy on a file-name match for exactly this reason; publisher and
  path matching exist in the engine and need CLI flags.
- **Sessions are in memory**, so restarting the service clears them. That is deliberate: a
  restart should not silently extend access.

## Troubleshooting

**Broker says the service is unreachable.** Start the service first. The broker retries with
exponential backoff and says so each time.

**`UnauthorizedAccessException` accepting an IPC connection.** Was a bug where the pipe's own
DACL denied the service `WRITE_DAC` on additional instances. Fixed — rebuild if you are on an
older checkout.

**Nothing happens when you open a protected app.** Check `& $svc policies` lists it and is
`on`, and that the file name matches exactly (`notepad.exe`, lower case).

**No log output at all.** `appsettings.json` must be beside the executable. Both hosts pin
their content root to the executable's directory, so this should not recur, but a partial
copy of the output folder will do it.

**Stale binaries.** The broker's output folder changed when its TFM was versioned. If you
have an old `bin\Release\net10.0-windows` folder under `SecureAgent.Broker`, delete it — it
contains a pre-change build that will run and misbehave.

**"You must install .NET to run this application."** The SDK on this machine lives in
`%LOCALAPPDATA%\Microsoft\dotnet`, which is not one of the locations the app host searches by
default, and there is no registry entry pointing at it. `DOTNET_ROOT` is what bridges the
gap. It is set at user level, so a **newly opened** terminal works — but any shell opened
before that variable existed still has the old environment and will fail. Open a fresh
terminal, or set it for the session:

    $env:DOTNET_ROOT = "$env:LOCALAPPDATA\Microsoft\dotnet"

This is a development-time wrinkle, but it points at a real packaging decision for later:
the installer should ship a **self-contained** publish (`dotnet publish -r win-x64
--self-contained`) rather than a framework-dependent one. A security agent that silently
fails to start because a machine has no .NET runtime, or has it somewhere unexpected, is
worse than one that is a hundred megabytes larger.
