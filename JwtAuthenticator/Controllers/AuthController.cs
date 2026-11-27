using JwtAuthenticator.Data;
using JwtAuthenticator.DTOs.Requests;
using JwtAuthenticator.DTOs.Responses;
using JwtAuthenticator.Entities;
using JwtAuthenticator.Options;
using JwtAuthenticator.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using JwtAuthenticator.Constants;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using System.Data;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;

namespace JwtAuthenticator.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly IEmailSender _emailSender;
    private readonly JwtOptions _jwtOptions;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext context,
        ITokenService tokenService,
        IEmailSender emailSender,
        IOptions<JwtOptions> jwtOptions,
        IMemoryCache cache,
        IConfiguration configuration
        )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _context = context;
        _tokenService = tokenService;
        _emailSender = emailSender;
        _jwtOptions = jwtOptions.Value;
        _cache = cache;
        _configuration = configuration;
    }

    // =========================================================================
    // 1. REGISTER
    // =========================================================================
    [EnableRateLimiting("auth-strict")]
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        var existingUser = await _userManager.FindByEmailAsync(request.Email);
        if(existingUser is not null)
        {
            return Problem(
                title: "Registration failed",
                detail: "An account with this email already exists.",
                statusCode: StatusCodes.Status409Conflict
                );
        }

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName,
            CreatedAtUtc = DateTime.UtcNow
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if(!result.Succeeded)
        {
            return ValidationProblem(new ValidationProblemDetails(
                result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray())));
        }

        await _userManager.AddToRoleAsync(user, Roles.User);

        // Generate Email Confirmation Token (URL-safe encoded)
        var confirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(confirmationToken));

        // Send Confirmation Email (logged to console in Dev)
        var confirmationLink = $"{Request.Scheme}://{Request.Host}/api/auth/confirm-email?userId={user.Id}&token={encodedToken}";
        await _emailSender.SendEmailAsync(
            user.Email,
            "Confirm your email",
            $"Please confirm your account by visiting: {confirmationLink}");

        return CreatedAtAction(nameof(GetCurrentUser), new { }, new
        {
            Message = "Registration successful. Please check your email (or Console Log) to confirm your account.",
            UserId = user.Id
        });
    }

    // =========================================================================
    // 2. CONFIRM EMAIL
    // =========================================================================
    [HttpGet("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if(user is null)
        {
            return Problem(title: "Invalid request", detail: "User not found.", statusCode: StatusCodes.Status400BadRequest);
        }

        var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
        var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

        var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
        if(!result.Succeeded)
        {
            return Problem(title: "Confirmation failed", detail: "Invalid or expired confirmation token.", statusCode: StatusCodes.Status400BadRequest);
        }

        return Ok(new { message = "Email Confirmed successfully. You can now log in." });
    }

    // =========================================================================
    // 3. LOGIN (Issues Access + Refresh Token Pair)
    // =========================================================================
    [EnableRateLimiting("auth-strict")]
    [HttpPost("login")]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if(user is null)
        {
            return Problem(title: "Authentication failed", detail: "Invalid email or password.", statusCode: StatusCodes.Status401Unauthorized);
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if(signInResult.IsLockedOut)
        {
            return Problem(
                title: "Account locked",
                detail: "Too many failed login attempts. Please try again later.",
                statusCode: StatusCodes.Status423Locked
                );
        }

        if(!signInResult.Succeeded)
        {
            return Problem(
                title: "Authentication Failed",
                detail: "Invalid Email or Password.",
                statusCode: StatusCodes.Status401Unauthorized
            );
        }

        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (string.IsNullOrWhiteSpace(request.TwoFactorCode))
            {
                return Accepted(new
                {
                    RequiredTwoFactor = true,
                    Message = "Two Factor authentication code is required."
                });
            }

            var cleanCode = request.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var validTotp = await _userManager.VerifyTwoFactorTokenAsync(
                user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                cleanCode);

            if(!validTotp)
            {
                var recovery = await _userManager.RedeemTwoFactorRecoveryCodeAsync(user, cleanCode);
                if(!recovery.Succeeded)
                {
                    await _userManager.AccessFailedAsync(user);
                    return Problem(
                        title: "Invalid 2FA code",
                        detail: "The two-factor authentication or recovery code is invalid.",
                        statusCode: StatusCodes.Status401Unauthorized
                    );
                }
            }
        }

        // Generate Access Token and Refresh Token 
        var accessToken = await _tokenService.GenerateAccessTokenAsync(user);
        var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        if(_jwtOptions.UseHttpOnlyRefreshCookie)
        {
            SetRefreshTokenCookie(refreshToken.Token, refreshToken.ExpiresOnUtc);
        }

        var response = new AuthResponse(
            AccessToken: accessToken,
            RefreshToken: _jwtOptions.UseHttpOnlyRefreshCookie ? null : refreshToken.Token,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpiryMinutes),
            UserId: user.Id,
            Email: user.Email!,
            FullName: $"{user.FirstName} {user.LastName}".Trim());

        return Ok(response);
    }

    // =========================================================================
    // 4. REFRESH TOKEN (Rotation + Replay Attack Detection)
    // =========================================================================
    [HttpPost("refresh-token")]
    public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] RefreshTokenRequest? request = null)
    {
        var incomingToken = ResolveRefreshToken(request);
        if(string.IsNullOrWhiteSpace(incomingToken))
        {
            return Problem(
                title: "Invalid token",
                detail: "Refresh token is missing.",
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var existingToken = await _context.RefreshTokens.Include(rt => rt.User).FirstOrDefaultAsync(rt => rt.Token == incomingToken);

        if(existingToken is null)
        {
            return Problem(title: "Invalid Token", detail: "Refresh Token not found.", statusCode: StatusCodes.Status401Unauthorized);
        }

        // REPLAY ATTACK DETECTION:
        // If an already-revoked token is submitted again, assume it was stolen!
        // Immediately revoke ALL active refresh tokens for this user.
        if(existingToken.IsRevoked)
        {
            await RevokeAllUserTokenAsync(existingToken.UserId, "Attempted reuse of a revoked refresh token (possible replay attack).");
            ClearRefreshTokenCookie();
            return Problem(title: "Security alert", detail: "Refresh token has already been used. All active sessions have been revoked.", statusCode: StatusCodes.Status401Unauthorized);
        }

        if(existingToken.IsExpired)
        {
            ClearRefreshTokenCookie();
            return Problem(title: "Token expired", detail: "Refresh token has expired. Please log in again.", statusCode: StatusCodes.Status401Unauthorized);
        }

        // Rotate the token: Generate a new pair and mark the old one as replaced
        var newRefreshToken = _tokenService.GenerateRefreshToken(existingToken.UserId);

        existingToken.RevokedOnUtc = DateTime.UtcNow;
        existingToken.ReasonRevoked = "Replaced by new token";
        existingToken.ReplacedByToken = newRefreshToken.Token;

        _context.RefreshTokens.Add(newRefreshToken);
        await _context.SaveChangesAsync();

        var newAccessToken = await _tokenService.GenerateAccessTokenAsync(existingToken.User);
        if (_jwtOptions.UseHttpOnlyRefreshCookie)
        {
            SetRefreshTokenCookie(newRefreshToken.Token, newRefreshToken.ExpiresOnUtc);
        }

        return Ok(new AuthResponse(
            AccessToken: newAccessToken,
            RefreshToken: _jwtOptions.UseHttpOnlyRefreshCookie ? null : newRefreshToken.Token,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpiryMinutes),
            UserId: existingToken.UserId,
            Email: existingToken.User.Email!,
            FullName: $"{existingToken.User.FirstName} {existingToken.User.LastName}".Trim()
            ));
    }

    // =========================================================================
    // 5. LOGOUT (Revoke Refresh Token)
    // =========================================================================
    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] RefreshTokenRequest? request = null)
    {
        var incomingToken = ResolveRefreshToken(request);
        if(string.IsNullOrWhiteSpace(incomingToken))
        {
            return Problem(title: "Invalid token", detail: "Refresh token is missing.", statusCode: StatusCodes.Status400BadRequest);
        }

        var existingToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == incomingToken);

        if(existingToken is null || !existingToken.IsActive)
        {
            ClearRefreshTokenCookie();
            return Problem(title: "Invalid token", detail: "Token is already inactive or does not exist.", statusCode: StatusCodes.Status400BadRequest);
        }

        existingToken.RevokedOnUtc = DateTime.UtcNow;
        existingToken.ReasonRevoked = "User logged out";
        await _context.SaveChangesAsync();

        ClearRefreshTokenCookie();
        return Ok(new { Message = "Logged out successfully." });
    }

    // =========================================================================
    // 6. FORGOT PASSWORD
    // =========================================================================
    [EnableRateLimiting("auth-strict")]
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        // SECURITY: Do NOT Reveal whether the email exists (prevents user enumeration).
        if(user is not null)
        {
            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(resetToken));

            await _emailSender.SendEmailAsync(
                user.Email!,
                "Reset Your Password",
                $"Use this token to reset your password: {encodedToken}");
        }

        return Ok(new { message = "If an account with that email exists, a password reset token has been sent." });
    }

    // =========================================================================
    // 7. RESET PASSWORD
    // =========================================================================
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if(user is null)
        {
            return Problem(title: "Reset failed", detail: "Invalid password reset request.", statusCode: StatusCodes.Status400BadRequest);
        }

        string decodedToken;
        try
        {
            var tokenBytes = WebEncoders.Base64UrlDecode(request.Token);
            decodedToken = Encoding.UTF8.GetString(tokenBytes);
        } 
        catch(FormatException)
        {
            return Problem(title: "Reset failed", detail: "Invalid reset token format.", statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await _userManager.ResetPasswordAsync(user, decodedToken, request.NewPassword);
        if(!result.Succeeded)
        {
            return ValidationProblem(new ValidationProblemDetails(
                result.Errors.GroupBy(e => e.Code).ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray())));
        }

        // Security Best Practice: Revoke all existing sessions when a password changes
        await RevokeAllUserTokenAsync(user.Id, "Password was reset.");
        return Ok(new { Message = "Password has been reset successfully. Please log in with your new password." });
    }


    // =========================================================================
    // 8. PROTECTED TEST ENDPOINT (Verify JWT Authentication Works)
    // =========================================================================
    [Authorize]
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        var email = User.FindFirstValue(ClaimTypes.Email) ?? User.FindFirstValue("email");
        var name = User.FindFirstValue("name");
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();
        return Ok(new
        {
            UserId = userId,
            Email = email,
            Name = name,
            Roles = roles
        });
    }

    // =========================================================================
    // 9. SETUP 2FA (Generate Secret Key & Authenticator URI)
    // =========================================================================
    [Authorize]
    [HttpPost("2fa/setup")]
    public async Task<IActionResult> SetupTwoFactor()
    {
        var user = await GetAuthenticatedUserAsync();
        if (user is null) return Unauthorized();

        var secretKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if(string.IsNullOrEmpty(secretKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            secretKey = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var issuer = Uri.EscapeDataString(_jwtOptions.Issuer);
        var account = Uri.EscapeDataString(user.Email ?? user.UserName ?? user.Id);
        var otpAuthUri = $"otpauth://totp/{issuer}:{account}?secret={secretKey}&issuer={issuer}&digits=6";

        return Ok(new
        {
            SharedKey = secretKey,
            AuthenticatorUri = otpAuthUri
        });
    }

    // =========================================================================
    // 10. ENABLE 2FA (Verify 6-Digit Code & Issue Recovery Codes)
    // =========================================================================
    [Authorize]
    [HttpPost("2fa/enable")]
    public async Task<IActionResult> EnableTwoFactor([FromBody] TwoFactorCodeRequest request)
    {
        var user = await GetAuthenticatedUserAsync();
        if (user is null) return Unauthorized();

        var cleanCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user,
            _userManager.Options.Tokens.AuthenticatorTokenProvider,
            cleanCode);

        if(!isValid)
        {
            return Problem(
                title: "Verification failed",
                detail: "Invalid authenticator code.",
                statusCode: StatusCodes.Status400BadRequest
            );
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        var recoveryCodes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return Ok(new
        {
            Message = "Two-factor authenticator enabled.",
            RecoveryCodes = recoveryCodes
        });
    }

    // =========================================================================
    // 11. DISABLE 2FA (Requires Valid TOTP Code)
    // =========================================================================
    [Authorize]
    [HttpPost("2fa/disable")]
    public async Task<IActionResult> DisableTwoFactor([FromBody] TwoFactorCodeRequest request)
    {
        var user = await GetAuthenticatedUserAsync();
        if(user is null)
        {
            return Unauthorized();
        }

        var cleanCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
        user,
        _userManager.Options.Tokens.AuthenticatorTokenProvider,
        cleanCode);

        if (!isValid)
        {
            return Problem(
                title: "Verification failed",
                detail: "Valid authenticator code is required to disable 2FA.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        return Ok(new { Message = "Two-factor authentication disabled." });
    }

    // =========================================================================
    // 12. EXTERNAL OAUTH LOGIN (Google / GitHub Challenge)
    // =========================================================================
    [HttpGet("external-login/{provider}")]
    public async Task<IActionResult> ExternalLogin(
        [FromRoute] string provider,
        [FromQuery] string returnUrl,
        [FromServices] IAuthenticationSchemeProvider schemeProvider
        )
    {
        var normalizedProvider = NormalizeProviderName(provider);
        if(normalizedProvider is null)
        {
            return Problem(
                title: "Unsupported provider",
                detail: "Supported providers are 'Google' and 'Github'.",
                statusCode: StatusCodes.Status400BadRequest
                );
        }

        // Check if this provider is already configured with ClientId and ClientSecret
        var scheme = await schemeProvider.GetSchemeAsync(normalizedProvider);
        if(scheme is null)
        {
            return Problem(
                title: "Provider not Configured.",
                detail: $"{normalizedProvider} OAuth credentials are not configured in appsettings.json.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        // Security: Prevent Open Redirect attacks (only allow configured CORS frontend origins)
        if(!IsAllowedReturnUrl(returnUrl))
        {
            return Problem(
                title: "Invalid returnUrl",
                detail: "The specific returnUrl is not in CorsSettings:AllowedOrigins.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var callbackUrl = Url.Action(nameof(ExternalCallback), new { returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(normalizedProvider, callbackUrl);

        return Challenge(properties, normalizedProvider);
    }

    // =========================================================================
    // 13. EXTERNAL OAUTH CALLBACK (Issues 60-Second One-Time Exchange Code)
    // =========================================================================
    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalCallback([FromQuery] string returnUrl, [FromQuery] string? remoteError = null)
    {
        if(!IsAllowedReturnUrl(returnUrl))
        {
            return BadRequest("Invalid returnUrl.");
        }

        if(!string.IsNullOrWhiteSpace(remoteError))
        {
            return Redirect($"{returnUrl}?error={Uri.EscapeDataString(remoteError)}");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if(info is null)
        {
            return Redirect($"{returnUrl}?error=external_login_failed");
        }

        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        if(string.IsNullOrWhiteSpace(email))
        {
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
            return Redirect($"{returnUrl}?error=email_not_provided");
        }

        // 1. Check if external logged in is already linked to a user
        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);

        if(user is null)
        {
            // 2. Check if an account with the same verified email already exists
            user = await _userManager.FindByEmailAsync(email);

            if (user is null)
            {
                var fullName = info.Principal.FindFirstValue(ClaimTypes.Name) ?? string.Empty;
                var nameParts = fullName.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);

                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    FirstName = nameParts.Length > 0 ? nameParts[0] : "User",
                    LastName = nameParts.Length > 1 ? nameParts[1] : string.Empty,
                    EmailConfirmed = true, // Already verified by Google/GitHub
                    CreatedAtUtc = DateTime.UtcNow
                };

                var createResult = await _userManager.CreateAsync(user);
                if (!createResult.Succeeded)
                {
                    await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
                    return Redirect($"{returnUrl}?error=user_creation_failed");
                }

                await _userManager.AddToRoleAsync(user, Roles.User);
            }

            // Link external provider to user account (AspNetUserLogins)
            await _userManager.AddLoginAsync(user, info);
        }

        // Clear the temporary external handshake cookie (keep API stateless)
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

        // Create a single-use 60-second code so raw JWTs NEVER appear in browser URLs
        var exchangeCode = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));

        _cache.Set($"ext_code:{exchangeCode}", user.Id, TimeSpan.FromSeconds(60));
        var separator = returnUrl.Contains('?') ? "&" : "?";

        return Redirect($"{returnUrl}{separator}code={exchangeCode}");
    }

    // =========================================================================
    // 14. EXCHANGE ONE-TIME CODE FOR JWT + REFRESH TOKEN PAIR
    // =========================================================================
    [HttpPost("external-exchange")]
    public async Task<ActionResult<AuthResponse>> ExternalExchange([FromBody] ExternalExchangeRequest request)
    {
        var cacheKey = $"ext_code:{request.Code}";
        if(!_cache.TryGetValue<string>(cacheKey, out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            return Problem(
                title: "Invalid or expired code",
                detail: "The external login exchange code is invalid or has expired.",
                statusCode: StatusCodes.Status401Unauthorized
            );
        }

        //Single-use: remove immediately so the code can never be redeemed twice
        _cache.Remove(cacheKey);

        var user = await _userManager.FindByIdAsync(userId);
        if(user is null)
        {
            return Unauthorized();
        }

        var accessToken = await _tokenService.GenerateAccessTokenAsync(user);
        var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

        _context.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        if (_jwtOptions.UseHttpOnlyRefreshCookie)
        {
            SetRefreshTokenCookie(refreshToken.Token, refreshToken.ExpiresOnUtc);
        }
        return Ok(new AuthResponse(
            AccessToken: accessToken,
            RefreshToken: _jwtOptions.UseHttpOnlyRefreshCookie ? null : refreshToken.Token,
            ExpiresAtUtc: DateTime.UtcNow.AddMinutes(_jwtOptions.AccessTokenExpiryMinutes),
            UserId: user.Id,
            Email: user.Email!,
            FullName: $"{user.FirstName} {user.LastName}".Trim()
        ));
    }

    // =========================================================================
    // HELPER: Revoke all active refresh tokens for a user
    // =========================================================================
    private async Task RevokeAllUserTokenAsync(string userId, string reason)
    {
        var activeTokens = await _context.RefreshTokens.Where(rt => rt.UserId == userId && rt.RevokedOnUtc == null && rt.ExpiresOnUtc > DateTime.UtcNow).ToListAsync();

        foreach(var token in activeTokens)
        {
            token.RevokedOnUtc = DateTime.UtcNow;
            token.ReasonRevoked = reason;
        }

        await _context.SaveChangesAsync();
    }

    private string? ResolveRefreshToken(RefreshTokenRequest? request)
    {
        if(_jwtOptions.UseHttpOnlyRefreshCookie && Request.Cookies.TryGetValue(_jwtOptions.RefreshCookieName, out var cookieToken) && !string.IsNullOrWhiteSpace(cookieToken))
        {
            return cookieToken;
        }

        return request?.RefreshToken;
    }

    private void SetRefreshTokenCookie(string token, DateTime expiresOnUtc)
    {
        Response.Cookies.Append(_jwtOptions.RefreshCookieName, token, BuildRefreshCookieOptions(expiresOnUtc));
    }

    private void ClearRefreshTokenCookie()
    {
        if(_jwtOptions.UseHttpOnlyRefreshCookie)
        {
            // path MUST match the path used when setting the cookie, otherwise the browser won't delete it!
            Response.Cookies.Delete(_jwtOptions.RefreshCookieName, new CookieOptions
            {
                Path = "/api/auth",
                HttpOnly = true,
                Secure = Request.IsHttps,
                SameSite = SameSiteMode.Strict
            });
        }
    }

    private CookieOptions BuildRefreshCookieOptions(DateTime expiresOnUtc) => new()
    {
        HttpOnly = true, // Blocks JavaScript
        Secure = Request.IsHttps, // HTTPS-only in production, still works on http://localhost Docker dev
        SameSite = SameSiteMode.Strict, //Blocks CSRF on same-site deployments
        Path = "/api/auth", // Browser only sends this cookie to /api/auth/* routes
        Expires = expiresOnUtc
    };

    private async Task<ApplicationUser?> GetAuthenticatedUserAsync()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        return userId is not null ? await _userManager.FindByIdAsync(userId) : null;
    }

    private static string? NormalizeProviderName(string provider) => provider.Trim().ToLowerInvariant() switch
    {
        "google" => "Google",
        "github" => "GitHub",
        _ => null
    };

    private bool IsAllowedReturnUrl(string returnUrl)
    {
        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var origin = $"{uri.Scheme}://{uri.Authority}";
        var allowedOrigins = _configuration.GetSection("CorsSettings:AllowedOrigins").Get<string[]>() ?? [];
        return allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase);
    }
}
