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

namespace JwtAuthenticator.Controllers
{
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

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ApplicationDbContext context,
            ITokenService tokenService,
            IEmailSender emailSender,
            IOptions<JwtOptions> jwtOptions)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _tokenService = tokenService;
            _emailSender = emailSender;
            _jwtOptions = jwtOptions.Value;
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

            // Generate Access Token and Refresh Token 
            var accessToken = await _tokenService.GenerateAccessTokenAsync(user);
            var refreshToken = _tokenService.GenerateRefreshToken(user.Id);

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            var response = new AuthResponse(
                AccessToken: accessToken,
                RefreshToken: refreshToken.Token,
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
        public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
        {
            var existingToken = await _context.RefreshTokens.Include(rt => rt.User).FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);

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

                return Problem(title: "Security alert", detail: "Refresh token has already been used. All active sessions have been revoked.", statusCode: StatusCodes.Status401Unauthorized);
            }

            if(existingToken.IsExpired)
            {
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

            return Ok(new AuthResponse(
                AccessToken: newAccessToken,
                RefreshToken: newRefreshToken.Token,
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
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request)
        {
            var existingToken = await _context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);
            if(existingToken is null || !existingToken.IsActive)
            {
                return Problem(title: "Invalid token", detail: "Token is already inactive or does not exist.", statusCode: StatusCodes.Status400BadRequest);
            }

            existingToken.RevokedOnUtc = DateTime.UtcNow;
            existingToken.ReasonRevoked = "User logged out";
            await _context.SaveChangesAsync();

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
    }
}
