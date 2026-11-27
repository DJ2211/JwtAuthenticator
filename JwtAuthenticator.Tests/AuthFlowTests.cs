using JwtAuthenticator.DTOs.Requests;
using JwtAuthenticator.DTOs.Responses;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

namespace JwtAuthenticator.Tests;
public class AuthFlowTests : IClassFixture<AuthTestFactory>
{
    private readonly HttpClient _client;

    public AuthFlowTests(AuthTestFactory factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Register_Login_And_AccessProtectedEndPoint_Succeeds()
    {
        var email = $"user_{Guid.NewGuid():N}@example.com";
        const string password = "Strong@Password123!";

        // 1. Register
        var regResponse = await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("Test", "User", email, password));
        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);

        // 2. Login
        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var auth = await loginResponse.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(auth);
        Assert.False(string.IsNullOrWhiteSpace(auth.AccessToken));

        // 3. Call protected /me endpoint
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", auth.AccessToken);

        var meResponse = await _client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);
    }

    [Fact]
    public async Task RefreshToken_ReplayAttack_RevokeAllUserSessions()
    {
        var email = $"replay_{Guid.NewGuid():N}@example.com";
        const string password = "Strong@Password123!";

        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("Replay", "Tester", email, password));

        var loginResp = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        var initialTokens = await loginResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);
        Assert.NotNull(initialTokens);

        // Legitimate rotation #1
        var rotateResp = await _client.PostAsJsonAsync("/api/auth/refresh-token", new RefreshTokenRequest(initialTokens.RefreshToken));
        Assert.Equal(HttpStatusCode.OK, rotateResp.StatusCode);
        var rotatedTokens = await rotateResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(rotatedTokens);

        // Attackers replays the OLD refresh token => Must Fail with 401
        var replayAttempt = await _client.PostAsJsonAsync("/api/auth/refresh-token", new RefreshTokenRequest(initialTokens.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, replayAttempt.StatusCode);

        // Legitimate user's NEW token must ALSO now be revoked!
        var legitimateRetry = await _client.PostAsJsonAsync("/api/auth/refresh-token", new RefreshTokenRequest(rotatedTokens.RefreshToken));
        Assert.Equal(HttpStatusCode.Unauthorized, legitimateRetry.StatusCode);
    }

    [Fact]
    public async Task Rbac_RegularUserGets403_AdminGets200()
    {
        // Regular user
        var userEmail = $"normal_{Guid.NewGuid():N}@example.com";
        const string password = "Strong@Password123!";

        await _client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("Normal", "User", userEmail, password));
        var userLogin = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest(userEmail, password));
        var userAuth = await userLogin.Content.ReadFromJsonAsync<AuthResponse>();

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userAuth!.AccessToken);
        var forbiddenResp = await _client.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.Forbidden, forbiddenResp.StatusCode);

        // Seeded Admin
        var adminLogin = await _client.PostAsJsonAsync("/api/auth/login", new LoginRequest("admin@jwtauthenticator.local", "Admin@Password123!"));
        var adminAuth = await adminLogin.Content.ReadFromJsonAsync<AuthResponse>();

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminAuth!.AccessToken);
        var adminResp = await _client.GetAsync("/api/admin/users");
        Assert.Equal(HttpStatusCode.OK, adminResp.StatusCode);
    }

    [Fact]
    public async Task CookieMode_LoginAndRefresh_SetsHttpOnlyCookieAndHidesJsonToken()
    {
        // Spin up a Cookie-mode client from the existing factory
        using var cookieFactory = new AuthTestFactory().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("JwtSettings:UseHttpOnlyRefreshCookie", "true");
        });

        var client = cookieFactory.CreateClient();
        var email = $"cookie_{Guid.NewGuid():N}@example.com";
        const string password = "Strong@Password123!";

        await client.PostAsJsonAsync("/api/auth/register", new RegisterRequest("Cookie", "Tester", email, password));

        // 1. Login -> RefreshToken in JSON must be null, Set-Cookie must contain HttpOnly
        var loginResp = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password));
        Assert.Equal(HttpStatusCode.OK, loginResp.StatusCode);

        var auth = await loginResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(auth);
        Assert.Null(auth.RefreshToken);

        Assert.True(loginResp.Headers.TryGetValues("Set-Cookie", out var setCookies));
        var cookieHeader = setCookies.First();
        Assert.Contains("refreshToken=", cookieHeader);
        Assert.Contains("httponly", cookieHeader, StringComparison.OrdinalIgnoreCase);

        // 2. Call /refresh-token with NO body (HttpClient automatically sends the Cookie!)
        var refreshResp = await client.PostAsync("/api/auth/refresh-token", content: null);
        Assert.Equal(HttpStatusCode.OK, refreshResp.StatusCode);

        var refreshed = await refreshResp.Content.ReadFromJsonAsync<AuthResponse>();
        Assert.NotNull(refreshed);
        Assert.Null(refreshed.RefreshToken);
        Assert.False(string.IsNullOrWhiteSpace(refreshed.AccessToken));
    }

    [Fact]
    public async Task ExternalAuth_SecurityGuardrails_RejectBadRequests()
    {
        // 1. Unsupported provider -> 400
        var badProvider = await _client.GetAsync("/api/auth/external-login/unknown?returnUrl=http://localhost:5173/callback");
        Assert.Equal(HttpStatusCode.BadRequest, badProvider.StatusCode);

        // 2. Unconfigured Google (no ClientId in appsettings) -> 400
        var unconfigured = await _client.GetAsync("/api/auth/external-login/google?returnUrl=http://localhost:5173/callback");
        Assert.Equal(HttpStatusCode.BadRequest, unconfigured.StatusCode);

        // 3. Invalid one-time exchange code -> 401
        var badCode = await _client.PostAsJsonAsync("/api/auth/external-exchange", new ExternalExchangeRequest("fake-code"));
        Assert.Equal(HttpStatusCode.Unauthorized, badCode.StatusCode);
    }
}
