using Microsoft.EntityFrameworkCore;

namespace SecureAgent.Infrastructure.Database;

/// <summary>
/// The local SQLite store: identities, encrypted templates, policies and the audit chain.
/// </summary>
/// <remarks>
/// <para>
/// Lives under <c>%ProgramData%\SecureAgent</c> and is owned by the Session 0 service. The
/// broker has no connection string and no access; it runs as the interactive user, who may
/// be the adversary.
/// </para>
/// <para>
/// Templates are stored as ciphertext only, so the database file itself is not the
/// confidentiality boundary — the TPM-wrapped key is. Whole-file encryption via SQLCipher
/// is a later addition that would add a native dependency for a marginal gain once the
/// sensitive column is already sealed.
/// </para>
/// </remarks>
public sealed class SecureAgentDbContext : DbContext
{
    /// <summary>Creates the context.</summary>
    public SecureAgentDbContext(DbContextOptions<SecureAgentDbContext> options)
        : base(options)
    {
    }

    /// <summary>Enrolled identities.</summary>
    public DbSet<UserEntity> Users => Set<UserEntity>();

    /// <summary>Encrypted biometric templates.</summary>
    public DbSet<FaceTemplateEntity> FaceTemplates => Set<FaceTemplateEntity>();

    /// <summary>Protected application policies.</summary>
    public DbSet<PolicyEntity> Policies => Set<PolicyEntity>();

    /// <summary>Policy-to-identity authorisations.</summary>
    public DbSet<PolicyUserEntity> PolicyUsers => Set<PolicyUserEntity>();

    /// <summary>The hash-chained audit log.</summary>
    public DbSet<SecurityEventEntity> SecurityEvents => Set<SecurityEventEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.Entity<UserEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.WindowsSid);
            e.HasMany(x => x.Templates)
             .WithOne(t => t.User!)
             .HasForeignKey(t => t.UserId)
             // Deleting an identity destroys its biometric templates in the same
             // transaction. Consent withdrawal must not be able to leave orphans behind.
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<FaceTemplateEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.ModelId });
        });

        modelBuilder.Entity<PolicyEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.MatchKind, x.MatchValue });
            e.HasMany(x => x.AuthorizedUsers)
             .WithOne(p => p.Policy!)
             .HasForeignKey(p => p.PolicyId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PolicyUserEntity>(e =>
        {
            e.HasKey(x => new { x.PolicyId, x.UserId });
            e.HasOne(x => x.User!)
             .WithMany()
             .HasForeignKey(x => x.UserId)
             // Removing an identity revokes its authorisations rather than orphaning them.
             // The policy engine treats an empty authorised list as deny, so this fails
             // closed.
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<SecurityEventEntity>(e =>
        {
            e.HasKey(x => x.Id);

            // Sequence defines chain order and must be dense and unique; the repository
            // assigns it under the same lock that computes the hash link.
            e.HasIndex(x => x.Sequence).IsUnique();

            // The sync outbox drains on this.
            e.HasIndex(x => new { x.Synced, x.Sequence });

            e.HasIndex(x => x.Timestamp);
        });

        base.OnModelCreating(modelBuilder);
    }
}
