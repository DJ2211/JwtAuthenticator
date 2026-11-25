namespace JwtAuthenticator.DTOs.Requests;

public record LoginRequest(
    string Email,
    string Password
);
