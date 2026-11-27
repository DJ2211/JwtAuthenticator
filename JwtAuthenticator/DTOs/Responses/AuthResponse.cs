namespace JwtAuthenticator.DTOs.Responses
{
    public record AuthResponse(
        string AccessToken,
        string? RefreshToken,
        DateTime ExpiresAtUtc,
        string UserId,
        string Email,
        string FullName
    );
}
