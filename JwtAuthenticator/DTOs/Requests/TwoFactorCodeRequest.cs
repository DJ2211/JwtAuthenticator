namespace JwtAuthenticator.DTOs.Requests;

public record TwoFactorCodeRequest(
    string Code
);
