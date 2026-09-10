# Development setup

## What actually runs today

Be clear about this before you spend time on it. The repository is at **Phase 0**: the
structure, the audit chain, the contracts and the build guards exist and are tested. The
product does not.

| Works | Does not exist yet |
|---|---|
| Solution builds, 40 tests pass | Face recognition (P3) |
| Hash-chained audit records | Camera capture, Windows Hello (P3) |
| Two-clock abstraction | Foreground window monitoring (P2) |
| Untrusted-input normalisation | Policy evaluation (P4) |
| Schema ↔ C# parity gate | Overlay / enforcement (P4) |
| Service and broker start and log | Installer, service registration (P5) |

Running `SecureAgent.Service` today starts a host, writes one startup line, and idles.
It protects nothing. There is no installer, and there is nothing to install.

## Prerequisites

- **Windows 11** — the service and broker target `net10.0-windows`
- **.NET 10 SDK** (10.0.100 or later; `global.json` rolls forward within the 10.x line)
- **Git**
- Optional: VS Code with the C# Dev Kit extension, or Visual Studio 2022 17.14+

`SecureAgent.Core`, `SecureAgent.Contracts`, `SecureAgent.Face` and `SecureAgent.Tests`
target plain `net10.0` and build on Linux and macOS too. That is deliberate and CI enforces
it — see architecture rule 20.

### Installing the .NET 10 SDK

    winget install Microsoft.DotNet.SDK.10

If winget stalls (it downloads through Delivery Optimization, which fails silently on some
networks), use the official script instead — it installs per-user and needs no admin:

    Invoke-WebRequest https://dot.net/v1/dotnet-install.ps1 -OutFile dotnet-install.ps1
    .\dotnet-install.ps1 -Channel 10.0 -Quality GA

That installs to `%LOCALAPPDATA%\Microsoft\dotnet`, which is **not on PATH by default**.
Add it once, per-user, no admin required:

    $d = "$env:LOCALAPPDATA\Microsoft\dotnet"
    [Environment]::SetEnvironmentVariable(
        "PATH", [Environment]::GetEnvironmentVariable("PATH","User") + ";$d", "User")
    [Environment]::SetEnvironmentVariable("DOTNET_ROOT", $d, "User")

Open a new terminal, then confirm:

    dotnet --version    # expect 10.0.x

## Build and test

    git clone https://github.com/marouakhalilai/ADEEB.git
    cd ADEEB
    dotnet restore SecureAgent.slnx
    dotnet build SecureAgent.slnx -c Release
    dotnet test SecureAgent.slnx -c Release

Expected: 7 projects, 0 warnings, 0 errors, 40 tests passing.

The portable subset — the same set CI runs on Linux:

    dotnet test --filter Category=Portable

## Running it

Both processes run as ordinary console applications during development. Neither needs to be
installed as a Windows service to start, and you should not install them as services yet.

    dotnet run --project windows/SecureAgent.Service   # Session 0 half
    dotnet run --project windows/SecureAgent.Broker    # interactive-session half

They do not talk to each other yet; the named pipe arrives in Phase 2.

Logs go to the console and to `%ProgramData%\SecureAgent\logs\service-<date>.log`, rolling
daily, 14 files retained. Configure in `windows/SecureAgent.Service/appsettings.json`.

## Before you touch the face engine

`scripts/fetch-models.ps1` downloads the ONNX weights and **refuses to run** while
`models/provenance.md` still contains `PENDING` entries. That is intentional, not a bug.

Model weights carry licences independent of the runtime that executes them, and several
popular high-accuracy face models are published for non-commercial research use only.
Discovering that after a threshold has been calibrated costs the FAR/FRR baseline, the
spoof corpus results and the CI regression gate. Resolve the licences first.

## Things that will bite you

**Restore is slow the first time.** It pulls roughly 100 MB. On a poor connection NuGet
times out per-package and retries; a restore taking 10+ minutes is not stuck.

**Never write a literal control character into `SecureAgent.Core/Audit`.** The canonical
hash form uses U+001F as a field separator, written as the escape `'\u001F'`. A literal
control character in source is at the mercy of editor encoding and git filters, and
changing that byte invalidates every audit chain already written. `.gitattributes` pins
those files to LF for the same reason.

**`TreatWarningsAsErrors` is on, and NuGet auditing is set to `all` at `low` severity.**
A dependency with a known advisory fails the build rather than printing a warning. That is
deliberate — it is how `SQLitePCLRaw.lib.e_sqlite3` 2.1.10 (GHSA-2m69-gcr7-jv3q) was caught
on the first restore of this repository. Do not relax it to get a build through; bump the
package in `Directory.Packages.props` instead.

**Package versions live only in `Directory.Packages.props`.** Adding `Version=` to a
`PackageReference` is an error under Central Package Management.

**PowerShell's `>>` writes UTF-16.** Appending to a UTF-8 file with `echo "x" >> file.md`
interleaves null bytes, which render as spaces between every character. Use
`Add-Content -Encoding utf8`.

## Repository conventions

`CLAUDE.md` carries the architecture rules. Rules 18–25 are the ones a growing codebase
erodes first — particularly rule 18, the Session 0 split, which is always tempting to
violate to make one feature easier.

`docs/implementation-plan.md` has the phase table, exit criteria and blocking gates. A
phase is not done until its exit criterion passes.
