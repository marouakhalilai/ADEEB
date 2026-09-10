namespace SecureAgent.Core.Domain;

/// <summary>
/// The kind of audit record. Mirrors <c>schema/security-event.schema.json</c>; the two
/// are kept in step by <c>SchemaParityTests</c>.
/// </summary>
public enum EventKind
{
    AppActivated,
    VerificationRequested,
    VerificationSucceeded,
    VerificationFailed,
    VerificationInconclusive,
    VerifierUnavailable,
    SessionOpened,
    SessionExpired,
    AbsenceDetected,
    EnforcementApplied,
    RecoveryCodeUsed,
    EnrollmentCompleted,
    EnrollmentRevoked,
    PolicyChanged,
    PresenceDegraded,
    BrokerRestarted,
    TamperSuspected,
    EngineFault,
    VaultFault,
    ClockAnomaly,
    SessionChanged,
    ChainVerificationFailed,
}

/// <summary>Deterministically assigned by the service. The AI layer never rewrites it.</summary>
public enum Severity
{
    Info,
    Notice,
    Warning,
    High,
    Critical,
}

/// <summary>What happened to the access attempt.</summary>
public enum Outcome
{
    Allowed,
    Denied,

    /// <summary>
    /// Access proceeded, but not at the assurance the policy asked for — for example the
    /// camera was held by another process and the policy's fallback was to allow. Distinct
    /// from <see cref="Allowed"/> so that telemetry can separate "protected" from
    /// "nominally protected" (plan §05).
    /// </summary>
    Degraded,

    NotApplicable,
}

/// <summary>Which rung of the verifier ladder produced a result (plan §03).</summary>
public enum VerifierKind
{
    None,

    /// <summary>Rung 0 — an unexpired authentication session. No hardware touched.</summary>
    Session,

    /// <summary>Rung 1 — Windows Hello. Proves the account owner is present.</summary>
    WindowsHello,

    /// <summary>Rung 2 — the local ONNX pipeline. Proves <em>which</em> enrolled identity is present.</summary>
    LocalFace,

    /// <summary>Rung 3 — knowledge factor, for machines with no usable camera.</summary>
    Pin,

    /// <summary>The break-glass path. Always Critical severity (plan §06).</summary>
    RecoveryCode,
}

/// <summary>
/// Coarse buckets only. A raw similarity score is a biometric proxy and is never
/// persisted or logged (CLAUDE.md rule 25).
/// </summary>
public enum ConfidenceBucket
{
    None,
    Low,
    Medium,
    High,
}

/// <summary>The minimum rung a policy will accept.</summary>
public enum AssuranceLevel
{
    /// <summary>Any verifier, including PIN. For low-stakes applications.</summary>
    Any,

    /// <summary>Requires a biometric rung — Hello or the local face pipeline.</summary>
    Biometric,

    /// <summary>
    /// Requires Windows Hello or IR hardware. The only level that should be described to
    /// users as a security control rather than a deterrent (plan §01).
    /// </summary>
    HelloOrIr,
}

/// <summary>What to do when verification fails. Ordered by escalating disruption.</summary>
public enum FailureAction
{
    Overlay,
    Minimize,
    LockApp,
    LockWorkstation,

    // Terminate is deliberately absent. Killing a user's process loses their work and
    // generates support load out of proportion to the benefit (plan §06).
}

/// <summary>
/// What to do when no verifier of the required assurance is available at all — the
/// camera is held by another application, privacy settings revoked access, or there is
/// no capture device. This case fires many times a day in the field and every policy
/// must answer it explicitly (plan §05).
/// </summary>
public enum UnavailableAction
{
    /// <summary>Allow and log <c>Degraded</c>. The consumer-tier default.</summary>
    AllowAndWarn,

    /// <summary>Fall back to the PIN rung.</summary>
    RequirePin,

    /// <summary>Treat as a failure and apply the policy's <see cref="FailureAction"/>.</summary>
    Enforce,
}

/// <summary>How aggressively to re-verify presence after the initial check.</summary>
public enum ContinuousMode
{
    Off,

    /// <summary>Re-verify only while the protected application holds the foreground.</summary>
    OnForeground,

    /// <summary>Re-verify while the application is running, foreground or not.</summary>
    Always,
}

/// <summary>
/// How an executable was matched to a policy, in descending order of strength.
/// Recorded on every event so telemetry shows how often we fall back to the weak rule.
/// </summary>
public enum AppMatchKind
{
    /// <summary>Authenticode publisher. Survives updates and relocation; resists renamed copies.</summary>
    PublisherSignature,

    /// <summary>Full executable path. Breaks when an update relocates the binary.</summary>
    FullPath,

    /// <summary>
    /// File name only. Trivially defeated by copying and renaming a binary — acceptable
    /// as a convenience for unsigned applications, never as the sole control on a
    /// <see cref="AssuranceLevel.HelloOrIr"/> policy.
    /// </summary>
    FileName,

    Unresolved,
}

/// <summary>The enforcement action actually applied.</summary>
public enum EnforcementAction
{
    None,
    Overlay,
    Minimize,
    LockApp,
    LockWorkstation,
}
