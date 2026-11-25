# JwtAuthenticator (.NET 10) + C# MCP Server

A production-ready, open-source **ASP.NET Core (.NET 10)** authentication starter implementing **OAuth 2.0 / 2.1 JWT Bearer** security patterns, multi-database support, automated integration tests, and a native **C# Model Context Protocol (MCP) Server** for AI-assisted project scaffolding.

## Key Security & Engineering Features

- **JWT Access + Refresh Token Rotation:** Short-lived HMAC-SHA256 JWTs (`15 min`) paired with cryptographically random 64-byte refresh tokens.
- **Replay Attack Detection:** Reusing an already-rotated refresh token automatically revokes **all active sessions** for that user.
- **Account Lockout & Brute-Force Protection:** Enforces ASP.NET Identity lockouts (`SignInManager.CheckPasswordSignInAsync`) + IP-based `RateLimiter` (`429 Too Many Requests`).
- **Complete Auth Flows:** Register, URL-safe Email Confirmation, Login, Refresh Token, Logout, Forgot Password (with user-enumeration protection), and Reset Password (revokes existing sessions).
- **RBAC & Auto-Seeding:** Pre-seeded `Admin` / `User` roles and protected admin endpoints (`[Authorize(Roles = "Admin")]`).
- **Validation & Observability:** Global `FluentValidation` action filter, `.NET 10` `IExceptionHandler` returning RFC 7807 `ProblemDetails`, and `/health` database checks.
- **Multi-Database Ready:** Switch between **SQLite** (default), **PostgreSQL**, and **SQL Server** via `appsettings.json`.
- **Scalar OpenAPI UI:** Interactive API docs with built-in JWT Bearer auth at `/scalar/v1`.

## Project Structure

- `JwtAuthenticator/` — .NET 10 Web API (Controllers, Identity, EF Core, TokenService, Validators, Rate Limiting)
- `JwtAuthenticator.Tests/` — Integration tests using `WebApplicationFactory<Program>` and isolated SQLite databases
- `JwtAuthenticator.McpServer/` — C# MCP Server (`ModelContextProtocol`) for scaffolding and frontend client generation

## Quick Start

```bash
# 1. Apply migrations (SQLite default)
cd JwtAuthenticator
dotnet ef database update

# 2. Run the API
dotnet run
```

Open **`https://localhost:<PORT>/scalar/v1`** to explore and test all endpoints interactively.

### Run Integration Tests
```bash
dotnet test JwtAuthenticator.Tests/JwtAuthenticator.Tests.csproj
```

## C# MCP Server (`JwtAuthenticator.McpServer`)

Connect the MCP server to Claude Desktop, Cursor, or Antigravity:

```json
{
  "mcpServers": {
    "jwt-authenticator": {
      "command": "dotnet",
      "args": [
        "run",
        "--project",
        "<PATH_TO_REPO>/JwtAuthenticator.McpServer/JwtAuthenticator.McpServer.csproj"
      ]
    }
  }
}
```

### Available MCP Tools
- `scaffold_auth_project` — Clones the starter, renames namespaces, generates a fresh cryptographic `SecretKey`, and configures `sqlite` / `postgres` / `sqlserver` + CORS.
- `generate_frontend_auth_client` — Outputs `react-axios`, `nextjs-fetch`, or `angular` auth clients with a **Single-Flight Refresh Mutex** (prevents parallel `401` refreshes from triggering replay detection).
- `audit_security_config` — Audits `appsettings.json` for weak JWT keys, default passwords, oversized lifetimes, or wildcard CORS.
- `switch_database_provider` — Updates database provider and connection string configuration.

## Endpoints Overview

| Method | Route | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Create user & dispatch confirmation link |
| `GET` | `/api/auth/confirm-email` | Verify email token |
| `POST` | `/api/auth/login` | Authenticate & issue Access/Refresh tokens |
| `POST` | `/api/auth/refresh-token` | Rotate refresh token (with replay protection) |
| `POST` | `/api/auth/logout` | Revoke active refresh token |
| `POST` | `/api/auth/forgot-password` | Generate URL-safe password reset token |
| `POST` | `/api/auth/reset-password` | Reset password & revoke active sessions |
| `GET` | `/api/auth/me` | Return authenticated user claims |
| `GET` | `/api/admin/users` | Admin-only user list |
| `POST` | `/api/admin/promote` | Promote user to `Admin` role |
| `GET` | `/health` | Database connectivity health check |