using JwtAuthenticator.Entities;

namespace JwtAuthenticator.Services;
public interface ITokenService
{
    Task<string> GenerateAccessTokenAsync(ApplicationUser user);
    RefreshToken GenerateRefreshToken(string userId);
}
