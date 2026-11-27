namespace JwtAuthenticator.Options
{
    public class JwtOptions
    {
        public const string SectionName = "JwtSettings";
        public string SecretKey { get; init; } = string.Empty;
        public string Issuer { get; init; } = string.Empty;
        public string Audience { get; init; } = string.Empty;
        public int AccessTokenExpiryMinutes { get; init; } = 15; // Short lived for security
        public int RefreshTokenExpiryDays { get; init; } = 7; // Longer-lived session

        // V2: Toggle HttpOnly cookie delivery for Refresh Token
        public bool UseHttpOnlyRefreshCookie { get; init; } = false;
        public string RefreshCookieName { get; init; } = "refreshToken";
    }
}
