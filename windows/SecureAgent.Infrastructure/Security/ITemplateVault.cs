using SecureAgent.Face.Abstractions;

namespace SecureAgent.Infrastructure.Security;

/// <summary>
/// Stores and retrieves enrolled face templates.
/// </summary>
/// <remarks>
/// <para>
/// Implemented only inside the core service. The broker never references this type — it
/// runs as the user and must not be able to read a template (plan §02).
/// </para>
/// <para>
/// The encryption design, spelled out because it is easy to weaken by accident:
/// </para>
/// <list type="bullet">
/// <item>
/// Templates are sealed with AES-256-GCM under a data key that exists only in memory.
/// </item>
/// <item>
/// That data key is wrapped by a key held in the CNG Microsoft Platform Crypto Provider,
/// which is TPM-resident and non-exportable. Where no TPM exists, DPAPI at machine scope
/// plus a SYSTEM-ACL'd entropy file is the fallback — weaker, and recorded as such in the
/// device's reported posture.
/// </item>
/// <item>
/// The GCM additional-authenticated-data carries <c>machineGuid ‖ userSid ‖ templateId</c>.
/// This is what makes a stolen database useless elsewhere, and it also prevents a template
/// being silently re-pointed at a different user within the same database — an attack that
/// plain encryption does nothing about.
/// </item>
/// </list>
/// </remarks>
public interface ITemplateVault
{
    /// <summary>
    /// Seals and stores a template for a user.
    /// </summary>
    /// <param name="userId">The enrolled identity.</param>
    /// <param name="vector">The embedding. The caller must clear its copy afterwards.</param>
    /// <param name="modelId">Model that produced it; templates are only comparable within a model.</param>
    /// <param name="modelVersion">Model version, so an upgrade can force re-enrolment.</param>
    /// <param name="quality">Capture quality, used to prefer better templates during enrolment.</param>
    /// <param name="ct">Cancels the operation.</param>
    Task<Guid> StoreAsync(
        Guid userId,
        float[] vector,
        string modelId,
        string modelVersion,
        float quality,
        CancellationToken ct);

    /// <summary>
    /// Opens the templates for the given users, for the duration of one match.
    /// </summary>
    /// <remarks>
    /// Returns a disposable so plaintext lifetime is bounded by a <c>using</c> rather than
    /// by garbage collection. Implementations zero the buffers on dispose.
    /// </remarks>
    Task<ITemplateLease> OpenAsync(IReadOnlyList<Guid> userIds, string modelId, CancellationToken ct);

    /// <summary>
    /// Destroys every template for a user, for consent withdrawal and account deletion.
    /// </summary>
    /// <returns>
    /// The number of templates destroyed, which becomes the deletion receipt written to
    /// the audit chain. That receipt is the evidence of erasure (plan §07).
    /// </returns>
    Task<int> DestroyAsync(Guid userId, CancellationToken ct);
}

/// <summary>
/// Decrypted templates, valid only until disposed.
/// </summary>
public interface ITemplateLease : IDisposable
{
    /// <summary>The decrypted templates, for the duration of the lease only.</summary>
    IReadOnlyList<EnrolledTemplate> Templates { get; }
}
