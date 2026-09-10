using System.Diagnostics;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using SecureAgent.Broker.Logging;
using SecureAgent.Core.Abstractions;
using SecureAgent.Core.Domain;
using Windows.Security.Credentials.UI;

namespace SecureAgent.Broker.Verification;

/// <summary>
/// Verification via Windows Hello.
/// </summary>
/// <remarks>
/// <para>
/// The strongest rung available without shipping our own biometric stack, and the cheapest
/// real security win in the product: Microsoft's anti-spoofing, IR hardware support, TPM-
/// backed credentials and the entire enrolment experience come for free, and no biometric
/// data ever reaches this process.
/// </para>
/// <para>
/// <b>What it proves, and what it does not.</b> Hello answers "the owner of this Windows
/// account is physically present and consented". It does not answer "which of the three
/// people enrolled on this machine is sitting here" — the API returns a yes or no, not an
/// identity. So this rung can satisfy a policy authorising the Windows account's own
/// identity, and cannot satisfy a multi-identity policy. That is what the local face engine
/// is for, and why the ladder exists rather than a single verifier.
/// </para>
/// <para>
/// Availability is probed on every call rather than cached: a user can remove their Hello
/// enrolment, and a laptop's camera can be claimed by another application, at any time.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows10.0.17763.0")]
public sealed class WindowsHelloVerifier : IIdentityVerifier
{
    private readonly Guid _accountUserId;
    private readonly ILogger<WindowsHelloVerifier> _logger;

    /// <summary>
    /// Creates the verifier.
    /// </summary>
    /// <param name="accountUserId">
    /// The enrolled identity corresponding to this Windows account. A Hello success is
    /// reported as this identity, because that is the only thing Hello actually attests.
    /// </param>
    /// <param name="logger">Logger.</param>
    public WindowsHelloVerifier(Guid accountUserId, ILogger<WindowsHelloVerifier> logger)
    {
        _accountUserId = accountUserId;
        _logger = logger;
    }

    /// <inheritdoc />
    public VerifierKind Kind => VerifierKind.WindowsHello;

    /// <inheritdoc />
    public AssuranceLevel ProvidedAssurance => AssuranceLevel.HelloOrIr;

    /// <inheritdoc />
    public async ValueTask<bool> IsAvailableAsync(CancellationToken ct)
    {
        try
        {
            var availability = await UserConsentVerifier
                .CheckAvailabilityAsync()
                .AsTask(ct);

            return availability == UserConsentVerifierAvailability.Available;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A machine with no Hello support throws rather than reporting unavailable on
            // some Windows builds. Unavailable is the honest answer either way.
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<VerificationResult> VerifyAsync(
        IdentityChallenge challenge,
        CancellationToken ct)
    {
        // Hello attests the account owner only. A policy that authorises other identities
        // cannot be satisfied here, and saying so is better than prompting and then
        // reporting a match for the wrong person.
        if (!challenge.AuthorizedUserIds.Contains(_accountUserId))
        {
            return VerificationResult.Unavailable(
                Kind,
                "Windows Hello attests the signed-in account only, which this policy does not authorise.");
        }

        // A silent presence check must not throw a modal prompt at someone who is working.
        if (!challenge.Interactive)
        {
            return VerificationResult.Unavailable(
                Kind,
                "Windows Hello requires an interactive prompt and cannot run a silent check.");
        }

        if (!await IsAvailableAsync(ct))
        {
            return VerificationResult.Unavailable(Kind, "Windows Hello is not available.");
        }

        var stopwatch = Stopwatch.StartNew();

        try
        {
            BrokerLog.VerificationStarting(_logger, challenge.MinimumAssurance, Kind);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(challenge.Timeout);

            var result = await UserConsentVerifier
                .RequestVerificationAsync("SecureAgent: confirm it is you to continue")
                .AsTask(timeout.Token);

            stopwatch.Stop();

            return result switch
            {
                UserConsentVerificationResult.Verified => new VerificationResult(
                    VerificationOutcome.Match,
                    _accountUserId,
                    Kind,
                    ProvidedAssurance,
                    ConfidenceBucket.High,
                    LivenessPassed: true,   // Hello performs its own presentation-attack detection.
                    (int)stopwatch.ElapsedMilliseconds,
                    null),

                // The user actively failed the biometric or cancelled. Distinguishing these
                // matters: a cancel is inconclusive, a retries-exhausted is a real failure.
                UserConsentVerificationResult.RetriesExhausted => new VerificationResult(
                    VerificationOutcome.NoMatch,
                    null,
                    Kind,
                    ProvidedAssurance,
                    ConfidenceBucket.None,
                    null,
                    (int)stopwatch.ElapsedMilliseconds,
                    "Retries exhausted."),

                UserConsentVerificationResult.Canceled => new VerificationResult(
                    VerificationOutcome.Inconclusive,
                    null,
                    Kind,
                    ProvidedAssurance,
                    ConfidenceBucket.None,
                    null,
                    (int)stopwatch.ElapsedMilliseconds,
                    "Cancelled by the user."),

                UserConsentVerificationResult.DeviceNotPresent
                    or UserConsentVerificationResult.NotConfiguredForUser
                    or UserConsentVerificationResult.DisabledByPolicy
                    or UserConsentVerificationResult.DeviceBusy =>
                    VerificationResult.Unavailable(Kind, result.ToString()),

                _ => new VerificationResult(
                    VerificationOutcome.Inconclusive,
                    null,
                    Kind,
                    ProvidedAssurance,
                    ConfidenceBucket.None,
                    null,
                    (int)stopwatch.ElapsedMilliseconds,
                    result.ToString()),
            };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Our own deadline elapsed. Inconclusive, not a failure: the user may simply
            // have walked away mid-prompt, and denying on that would be wrong.
            stopwatch.Stop();
            return new VerificationResult(
                VerificationOutcome.Inconclusive,
                null,
                Kind,
                ProvidedAssurance,
                ConfidenceBucket.None,
                null,
                (int)stopwatch.ElapsedMilliseconds,
                "Timed out waiting for the user.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            stopwatch.Stop();
            return VerificationResult.Unavailable(Kind, ex.GetType().Name);
        }
    }
}
