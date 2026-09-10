Yes. If you want to actually build this with **Claude Code**, I would structure it as a real Windows product rather than trying to make one giant Node/AI application.

The key architecture is:

**C# Windows agent + local face engine + local SQLite + optional NestJS cloud backend + AI security layer.**

Windows already provides biometric infrastructure, and Windows Hello face authentication uses an IR camera and local biometric representation rather than storing a normal face photograph. ([Microsoft Learn][1])

## 1. The stack I recommend

### Core Windows application

| Component        | Technology                                |
| ---------------- | ----------------------------------------- |
| Language         | **C#**                                    |
| Runtime          | **.NET 8/9**                              |
| Desktop UI       | **WinUI 3 / Windows App SDK**             |
| Background agent | **.NET Worker Service / Windows Service** |
| Windows APIs     | **Windows SDK / P/Invoke**                |
| Local DB         | **SQLite**                                |
| ORM              | Entity Framework Core                     |
| Config           | JSON + SQLite                             |
| Installer        | MSIX initially                            |
| IDE              | VS Code + C# Dev Kit / Visual Studio      |
| AI coding        | **Claude Code**                           |

Microsoft's current Windows development stack supports C# with .NET 8 or later and Windows App SDK/WinUI 3. ([Microsoft Learn][2])

### Face recognition

For the **first MVP**, I'd separate the face engine from the Windows agent:

```text
C# Agent
   ↓
Face Service
   ↓
OpenCV
   +
ONNX Runtime
   +
Face embedding model
```

This lets you replace the recognition model later without rewriting your Windows security agent.

For the **high-security version**, investigate Windows Hello/WBF instead of trying to recreate Microsoft's secure biometric stack. Windows exposes biometric APIs for verification/identification, although some modern secure-sensor scenarios have restrictions. ([Microsoft Learn][3])

---

# 2. Overall architecture

I'd build this:

```text
                    SECUREAGENT
                         │
        ┌────────────────┼─────────────────┐
        │                │                 │
        ▼                ▼                 ▼
 Windows Monitor    Face Engine       Policy Engine
        │                │                 │
        │                │                 │
        ▼                ▼                 ▼
 Active App          Camera            SQLite
 Process             Face              Policies
 Window              Embedding         Users
                     Liveness           Events
        │                │                 │
        └────────────────┼─────────────────┘
                         │
                         ▼
                  Decision Engine
                         │
               ┌─────────┴─────────┐
               ▼                   ▼
             ALLOW                BLOCK
                                   │
                         ┌─────────┼─────────┐
                         ▼         ▼         ▼
                       Lock      Hide      Close
```

Then later:

```text
                    CLOUD
                      │
                  NestJS API
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Devices      Policies     Events
                      │
                      ▼
                  AI Agent
                      │
                      ▼
               Security Analysis
```

---

# 3. Don't start with the AI

This is extremely important.

Your first version should **not** be:

> "Build an AI agent that protects Windows."

That's too broad.

Your first version should be:

> **"Protect a Windows application using local face verification."**

Once that works, add the AI.

---

# 4. Your MVP

I would make the first release do exactly this:

```text
Install SecureAgent
       ↓
Create user
       ↓
Enroll face
       ↓
Select protected application
       ↓
Chrome.exe
       ↓
User opens Chrome
       ↓
Agent detects Chrome
       ↓
Camera captures face
       ↓
Face verification
       ↓
MATCH
   ↓
Allow
```

If someone else opens it:

```text
Chrome
  ↓
Face check
  ↓
NO MATCH
  ↓
Block
  ↓
Log event
```

---

# 5. Project structure

Create this repository:

```text
secureagent/
│
├── src/
│   │
│   ├── SecureAgent.Agent/
│   │   ├── Program.cs
│   │   ├── AgentWorker.cs
│   │   ├── ProcessMonitor.cs
│   │   ├── WindowMonitor.cs
│   │   ├── EnforcementService.cs
│   │   └── AgentOptions.cs
│   │
│   ├── SecureAgent.Desktop/
│   │   ├── App.xaml
│   │   ├── MainWindow.xaml
│   │   ├── Views/
│   │   ├── ViewModels/
│   │   └── Services/
│   │
│   ├── SecureAgent.Face/
│   │   ├── FaceDetector.cs
│   │   ├── FaceEmbedder.cs
│   │   ├── FaceMatcher.cs
│   │   ├── LivenessDetector.cs
│   │   └── CameraService.cs
│   │
│   ├── SecureAgent.Core/
│   │   ├── Models/
│   │   ├── Interfaces/
│   │   ├── Policies/
│   │   └── Security/
│   │
│   ├── SecureAgent.Infrastructure/
│   │   ├── Database/
│   │   ├── Repositories/
│   │   └── Encryption/
│   │
│   └── SecureAgent.Tests/
│
├── models/
│
├── installer/
│
├── docs/
│
├── scripts/
│
├── .claude/
│   └── CLAUDE.md
│
├── README.md
└── SecureAgent.sln
```

This separation will save you a **huge amount of pain later**.

---

# 6. What each project does

### `SecureAgent.Agent`

The actual security daemon.

It monitors:

```text
Which user is logged in?
Which window is active?
Which process owns that window?
Is the application protected?
Should we authenticate?
```

Windows provides `GetForegroundWindow()` to retrieve the current foreground window. ([Microsoft Learn][4])

So conceptually:

```csharp
var hwnd = GetForegroundWindow();

var process = GetProcessFromWindow(hwnd);

if (policy.IsProtected(process.Name))
{
    AuthenticateUser();
}
```

---

# 7. Face service

Keep facial recognition isolated.

Interface:

```csharp
public interface IFaceRecognitionService
{
    Task<FaceEnrollmentResult> EnrollAsync();

    Task<FaceVerificationResult> VerifyAsync(
        string userId,
        CancellationToken cancellationToken);
}
```

Then you can have:

```text
IFaceRecognitionService
        │
        ├── LocalFaceRecognitionService
        │
        └── WindowsHelloService
```

This is a **very important design decision**.

You don't want your whole product tied to one face-recognition technology.

---

# 8. Database

SQLite:

```text
Users
─────
Id
Name
CreatedAt

FaceTemplates
─────────────
Id
UserId
Template
CreatedAt

Applications
────────────
Id
Name
ExecutablePath

Policies
───────
Id
ApplicationId
UserId
AuthenticationType
TimeoutSeconds
FailureAction

SecurityEvents
──────────────
Id
UserId
Application
EventType
Result
Timestamp
Metadata
```

Example:

```text
Policies

Chrome.exe
    ↓
User: Adeeb
    ↓
Authentication: Face
    ↓
Timeout: 300 sec
    ↓
Failure: Lock
```

---

# 9. Don't put raw photos in SQLite

Very important.

Avoid:

```text
FaceTemplates
    photo.jpg
```

Instead:

```text
Camera
   ↓
Face
   ↓
Embedding
   ↓
Encrypted template
   ↓
SQLite
```

Windows Hello itself uses a representation rather than storing the actual facial image for its authentication system. ([Microsoft Learn][1])

For your own engine, I'd encrypt the stored template and protect the encryption key using Windows security facilities.

---

# 10. Application monitoring

Your agent needs to determine:

```text
Foreground window
       ↓
HWND
       ↓
Process ID
       ↓
Process
       ↓
Executable
```

Example:

```text
HWND
 ↓
PID 18234
 ↓
chrome.exe
 ↓
Policy lookup
 ↓
Protected = TRUE
```

Then:

```text
Last authenticated:
2 minutes ago

Timeout:
5 minutes

→ Don't ask again
```

But:

```text
Last authenticated:
8 minutes ago

Timeout:
5 minutes

→ Re-authenticate
```

---

# 11. Don't authenticate every second

Bad:

```text
camera
 ↓
face
 ↓
face
 ↓
face
 ↓
face
 ↓
face
```

That wastes CPU and creates a terrible UX.

Instead:

```text
Application activated
        ↓
Check session
        ↓
Valid?
 ┌──────┴──────┐
YES           NO
 │              │
ALLOW          FACE
                ↓
             VERIFY
```

Then periodically reauthenticate.

---

# 12. The AI layer

Only after the above works.

Create:

```text
SecureAgent.AI
```

It receives structured events:

```json
{
  "timestamp": "...",
  "application": "chrome.exe",
  "user": "unknown",
  "faceMatch": false,
  "usbInserted": false,
  "failedAttempts": 3
}
```

The AI can reason over these events.

Example:

```text
10:03
Chrome opened
Unknown face

10:04
Chrome opened
Unknown face

10:05
USB device inserted

10:06
PowerShell launched
```

AI:

> HIGH RISK — repeated unauthorized access followed by removable-device insertion and PowerShell execution.

Then your deterministic security engine decides what action is allowed.

**Don't let the LLM directly control the machine.**

Instead:

```text
AI
 ↓
Recommendation
 ↓
Policy Engine
 ↓
Allowed action?
 ↓
Execute
```

That prevents an LLM mistake from becoming a security vulnerability.

---

# 13. Claude Code setup

This is where you can make Claude Code do a lot of the implementation.

Install:

```bash
claude
```

Then create your project.

```bash
mkdir SecureAgent
cd SecureAgent

git init
```

Create the solution:

```bash
dotnet new sln -n SecureAgent
```

Then:

```bash
dotnet new classlib -n SecureAgent.Core
dotnet new classlib -n SecureAgent.Face
dotnet new classlib -n SecureAgent.Infrastructure
dotnet new worker -n SecureAgent.Agent
```

And your desktop application separately with Windows App SDK/WinUI 3.

---

# 14. Give Claude Code a CLAUDE.md

This is probably the **most important thing** if you're going to use Claude Code.

Create:

```text
CLAUDE.md
```

Put this in it:

# SecureAgent

## Product

SecureAgent is a Windows desktop security agent that protects selected applications using local user authentication, facial verification, application monitoring, and security policies.

## Primary goal

Build a privacy-first Windows application that allows users to protect individual applications with local biometric/face authentication.

## Technology

- C#
- .NET 8+
- Windows 11
- Windows App SDK
- WinUI 3
- SQLite
- Entity Framework Core
- OpenCV
- ONNX Runtime
- Windows APIs / PInvoke
- xUnit
- Git

## Architecture

Projects:

- SecureAgent.Core
- SecureAgent.Agent
- SecureAgent.Desktop
- SecureAgent.Face
- SecureAgent.Infrastructure
- SecureAgent.Tests

## Architecture rules

1. Keep business logic independent of Windows UI.
2. Keep face recognition behind an interface.
3. Never store raw face photographs unless explicitly required for a temporary camera operation.
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

Initially test with:

- notepad.exe
- calc.exe
- chrome.exe

Do not implement destructive enforcement initially.

For the first version, when authentication fails, show a security overlay and log the event rather than forcefully terminating processes.

## Security

Never:

- upload face data without explicit user consent
- expose biometric embeddings through logs
- hardcode encryption keys
- trust an LLM with unrestricted machine control
- disable Windows security mechanisms
- implement kernel drivers for the MVP
- implement credential providers for the MVP

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

Use:

- nullable reference types
- dependency injection
- explicit interfaces at security boundaries
- small classes
- clear names
- XML documentation for public security APIs
- structured logging

Avoid:

- giant classes
- static global state
- unnecessary frameworks
- hidden background threads
- unsafe code unless absolutely required
- storing sensitive information in plain text

## Important

The project is a security product.

Correctness and security take priority over speed of implementation.

---

# 15. Then tell Claude Code what to build

Don't give Claude:

> "Build my entire AI Windows security product."

That's how you end up with a 10,000-line mess.

Instead, work incrementally.

### Prompt 1

```text
Read CLAUDE.md.

Create the SecureAgent solution structure.

Create:
- SecureAgent.Core
- SecureAgent.Agent
- SecureAgent.Face
- SecureAgent.Infrastructure
- SecureAgent.Tests

Configure dependency injection, nullable reference types and basic logging.

Do not implement facial recognition yet.

Build the entire solution and run all tests.
```

Then inspect what it does.

---

# 16. Prompt 2 — database

```text
Read CLAUDE.md.

Implement the SQLite database layer.

Create EF Core entities for:

User
FaceTemplate
ProtectedApplication
ApplicationPolicy
SecurityEvent

Create the DbContext.

Create migrations.

Add repositories where they provide real value.

Do not store raw facial images.

Add unit tests for database operations.

Build and run tests.
```

---

# 17. Prompt 3 — application monitoring

Then:

```text
Read CLAUDE.md.

Implement foreground application monitoring in SecureAgent.Agent.

Requirements:

1. Detect the current foreground window.
2. Resolve the owning process.
3. Resolve process name and executable path.
4. Publish an ApplicationActivated event.
5. Do not perform authentication yet.
6. Do not terminate or modify any process.
7. Handle processes that disappear during lookup.
8. Avoid busy loops and excessive CPU usage.
9. Add unit tests for policy-independent components.

Use Windows APIs appropriately.

Build and test.
```

Windows' `GetForegroundWindow` is the native API for obtaining the currently active foreground window. ([Microsoft Learn][5])

---

# 18. Prompt 4 — policy engine

```text
Read CLAUDE.md.

Implement the application policy engine.

Given:

- Windows user
- process name
- executable path
- current timestamp

return:

- Protected / NotProtected
- AuthenticationRequired / NotRequired
- Allowed / Denied

Implement authentication timeout.

Do not implement enforcement yet.

Add comprehensive unit tests.
```

---

# 19. Prompt 5 — face engine

Now the complicated part.

```text
Read CLAUDE.md.

Implement the face-recognition abstraction.

Create:

IFaceCamera
IFaceDetector
IFaceEmbedder
IFaceMatcher
IFaceRecognitionService

Keep model-specific implementation behind these interfaces.

The implementation must run locally.

Do not upload camera frames.

Do not store raw images.

Create a mock implementation for tests.

Do not connect the security policy engine to the real camera yet.

Build and test.
```

Then you can tell Claude which specific model/runtime you choose.

---

# 20. Prompt 6 — connect everything

```text
Read CLAUDE.md.

Connect:

ApplicationMonitor
        ↓
PolicyEngine
        ↓
AuthenticationService
        ↓
FaceRecognitionService
        ↓
DecisionEngine

Behavior:

If an unprotected application becomes active:
    do nothing.

If a protected application becomes active:
    check authentication session.

If session is valid:
    allow.

If session is expired:
    request face verification.

If face verification succeeds:
    create authentication session.

If face verification fails:
    create SecurityEvent.

For MVP, do not terminate the process.
Do not lock Windows.
Do not perform destructive actions.

Add tests.
```

---

# 21. Then build the UI

Your WinUI app should have:

```text
┌───────────────────────────────┐
│ SecureAgent                   │
├───────────────────────────────┤
│                               │
│ Security Status               │
│ ● Protected                   │
│                               │
│ Protected Applications        │
│                               │
│ Chrome.exe           ON       │
│ VSCode.exe            ON       │
│ WhatsApp.exe          OFF     │
│                               │
│ [+ Add Application]           │
│                               │
├───────────────────────────────┤
│ Security Events               │
│                               │
│ 02:31 Unknown face - Chrome   │
│ 02:29 Verified - VS Code     │
└───────────────────────────────┘
```

---

# 22. Eventually your architecture becomes

```text
                         SECUREAGENT
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
       Desktop             Agent              Face Engine
       WinUI 3           Windows Service      Local ML
          │                   │                   │
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                        Policy Engine
                              │
                        Decision Engine
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
           SQLite           Events          Enforcement
                                              │
                                    ┌─────────┼─────────┐
                                    ▼         ▼         ▼
                                  Overlay   Lock      Block
```

Then:

```text
                          CLOUD
                            │
                         NestJS
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
         Devices         Policies         Events
                                            │
                                            ▼
                                       AI Security
                                          Agent
                                            │
                                            ▼
                                     Risk Analysis
```

---

# 23. What NOT to build yet

Don't let Claude Code jump into:

❌ kernel drivers
❌ Windows Credential Provider
❌ antivirus functionality
❌ network packet inspection
❌ ransomware detection
❌ remote shell
❌ unrestricted AI actions
❌ automatic process killing
❌ custom biometric drivers

Those are **V2/V3 territory**.

Windows itself has a fairly deep biometric architecture, including sensor, matching and storage components, so writing a custom biometric driver is a completely different level of project. ([Microsoft Learn][6])

---

# 24. The roadmap I'd follow

### Phase 1 — 2–3 days

```text
C# project
SQLite
User
Application
Policy
Security events
```

### Phase 2 — 2–4 days

```text
Foreground window
      ↓
Process detection
      ↓
Policy engine
```

### Phase 3 — 3–7 days

```text
Camera
Face detection
Face embedding
Face matching
```

### Phase 4 — 2–4 days

```text
Face
 ↓
Policy
 ↓
Authentication session
 ↓
Security event
```

### Phase 5

```text
WinUI dashboard
```

### Phase 6

```text
Windows Service
Startup
Installer
Permissions
```

### Phase 7

```text
Continuous authentication
Liveness
Windows Hello integration
```

### Phase 8

```text
NestJS backend
Device management
Cloud policies
```

### Phase 9

```text
AI security agent
Risk scoring
Anomaly detection
Natural-language security reports
```

---

## One change I'd make to my previous recommendation

I would **not make the AI agent itself responsible for deciding whether a face is legitimate**.

Use:

```text
                 FACE MODEL
                     ↓
                Face result
                     ↓
              DETERMINISTIC
             POLICY ENGINE
                     ↓
                  ACTION
```

and separately:

```text
               SECURITY EVENTS
                     ↓
                  AI AGENT
                     ↓
              RISK ANALYSIS
                     ↓
             HUMAN / POLICY
                DECISION
```

That's much safer.

And for the highest-security mode, leverage **Windows Hello-compatible IR hardware** rather than pretending a normal webcam provides the same security. Microsoft specifically uses near-IR cameras and anti-spoofing for Windows Hello face authentication. ([Microsoft Learn][1])

### If I were you, I'd start here

**Windows 11 + C#/.NET 8 + WinUI 3 + Worker Service + SQLite + EF Core + OpenCV/ONNX + Claude Code.**

Build **Notepad protection first**, not Chrome. Once this works:

```text
Open Notepad
    ↓
Agent detects notepad.exe
    ↓
Policy says protected
    ↓
Face verification
    ↓
Match → allow
No match → security overlay + event
```

Then move to Chrome/WhatsApp/VS Code, then continuous authentication, then the AI layer.

[1]: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication?utm_source=chatgpt.com "Windows Hello face authentication | Microsoft Learn"
[2]: https://learn.microsoft.com/en-us/windows/apps/?utm_source=chatgpt.com "Windows app development documentation - Windows apps | Microsoft Learn"
[3]: https://learn.microsoft.com/en-us/windows/win32/secbiomet/biometric-service-api-portal?utm_source=chatgpt.com "Windows Biometric Framework - Win32 apps | Microsoft Learn"
[4]: https://learn.microsoft.com/en-us/windows/win32/winmsg/window-features?utm_source=chatgpt.com "Window Features - Win32 apps | Microsoft Learn"
[5]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow?utm_source=chatgpt.com "GetForegroundWindow function (winuser.h) - Win32 apps | Microsoft Learn"
[6]: https://learn.microsoft.com/en-us/windows/win32/secbiomet/biometric-framework-overview?utm_source=chatgpt.com "Biometric Framework overview - Win32 apps | Microsoft Learn"
