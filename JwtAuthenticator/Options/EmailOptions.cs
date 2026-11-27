namespace JwtAuthenticator.Options
{
    public class EmailOptions
    {
        public const string SectionName = "EmailSettings";
        public string Provider { get; init; } = "console";
        public string SmtpHost { get; init; } = "localhost";
        public int SmtpPort { get; init; } = 1025;
        public string FromEmail { get; init; } = "noreply@jwtauthenticator.local";
        public string FromName { get; init; } = "JwtAuthenticator";
        public string? Username { get; init; }
        public string? Password { get; init; }
        public bool UseSsl { get; init; } = false;
    }
}
