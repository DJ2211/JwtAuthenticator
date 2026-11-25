using Microsoft.AspNetCore.Components.Web;

namespace JwtAuthenticator.Entities;

public class RefreshToken
{
    public int Id { get; set; }

    // The Cryptographically secure random token string
    public string Token { get; set; } = string.Empty;

    public DateTime ExpiresOnUtc { get; set; }
    public DateTime CreatedOnUtc { get; set; } = DateTime.UtcNow;

    // If Revoked, record when and why
    public DateTime? RevokedOnUtc { get; set; }
    public string? ReasonRevoked { get; set; }

    // Token Rotation Tracking:
    // When a Refresh Token is used, it is revoked, and this points to the new token replacing it
    public string? ReplacedByToken { get; set; }

    // Foreign key to application User
    public string UserId { get; set; } = string.Empty;
    public ApplicationUser User { get; set; } = null!;

    // Helper properties (Calculated, not stored in DB)
    public bool IsExpired => DateTime.UtcNow >= ExpiresOnUtc;
    public bool IsRevoked => RevokedOnUtc is not null;
    public bool IsActive => !IsRevoked && !IsExpired;
}
