namespace JwtAuthenticator.DTOs.Requests;

public record ResetPasswordRequest(
    string Email,
    string Token,
    string NewPassword
);
