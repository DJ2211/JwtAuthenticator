using Microsoft.AspNetCore.Identity;
namespace JwtAuthenticator.Entities;

public class ApplicationUser : IdentityUser
{
    // Custom User Properties for your starter
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Navigation Property (One User can have multiple refresh tokens)
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
}
