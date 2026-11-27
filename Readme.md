# JwtAuthenticator (.NET 10) + Global C# MCP Server

[![NuGet](https://img.shields.io/nuget/v/JwtAuthenticator.McpServer.svg)](https://www.nuget.org/packages/JwtAuthenticator.McpServer)

A production-ready, open-source **ASP.NET Core (.NET 10)** authentication starter kit implementing **OAuth 2.0 / 2.1 JWT Bearer** security, **2FA (TOTP)**, **Google & GitHub OAuth**, **Docker + Mailpit**, and a globally installable **C# MCP Server** (`jwt-auth-mcp`) for zero-clone project scaffolding.

---

## Option A: Use the Global MCP Server (Zero Cloning Required!)

Install once globally from NuGet:
```bash
dotnet tool install -g JwtAuthenticator.McpServer
```

Add it to **Claude Desktop, Cursor, or Antigravity**:
```json
{
  "mcpServers": {
    "jwt-authenticator": {
      "command": "jwt-auth-mcp"
    }
  }
}
```

Then ask your AI assistant:
> *"Use `jwt-authenticator` to scaffold a new .NET 10 auth API named `MyStartupAuth` using PostgreSQL with `HttpOnly` cookies, and generate a React Axios client for it."*

### Available MCP Tools
- **`scaffold_auth_project`** — Scaffolds a renamed `.NET 10` project + `Dockerfile` + `docker-compose.yml` with a fresh 48-byte CSPRNG JWT key, database provider (`sqlite` / `postgres` / `sqlserver`), CORS, and optional `HttpOnly` cookie mode.
- **`generate_frontend_auth_client`** — Outputs `react-axios`, `nextjs-fetch`, or `angular` auth clients with a **Single-Flight Refresh Mutex** (supports both JSON and `HttpOnly` cookie modes).
- **`configure_email_provider`** — Switches `EmailSettings` between `console` and `smtp` (Mailpit / Resend / SendGrid / Gmail).
- **`configure_oauth_provider`** — Configures `Google` or `GitHub` OAuth 2.0 credentials.
- **`switch_database_provider`** — Updates `DatabaseProvider` and `ConnectionStrings`.
- **`audit_security_config`** — Audits `appsettings.json` for weak/placeholder JWT keys, oversized lifetimes, wildcard CORS, and exposed dev passwords.

---

## Option B: Run the Starter Directly with Docker

```bash
docker compose up --build
```
* **Scalar OpenAPI UI (with Bearer Auth):** `http://localhost:8080/scalar/v1`
* **Mailpit Web Email Inbox:** `http://localhost:8025`
* **Health Check:** `http://localhost:8080/health`

Or run locally without Docker (uses SQLite + console email logger):
```bash
cd JwtAuthenticator
dotnet ef database update
dotnet run
```

---

## Key Security & Engineering Features

- **JWT + Refresh Token Rotation:** Short-lived HMAC-SHA256 access tokens (`15 min`) + 64-byte cryptographic refresh tokens.
- **Replay Attack Detection:** Reusing an already-rotated refresh token automatically revokes **all active user sessions**.
- **Optional `HttpOnly` Cookie Mode:** Toggle `JwtSettings:UseHttpOnlyRefreshCookie` to store refresh tokens in `HttpOnly; SameSite=Strict` cookies scoped to `/api/auth`.
- **Stateless 2FA (TOTP):** RFC 6238 Authenticator App setup (`otpauth://`), 10 one-time Recovery Codes, and brute-force lockout enforcement.
- **External OAuth 2.0 (Google & GitHub):** Authorization Code flow with Open-Redirect validation and a 60-second single-use exchange code (`/api/auth/external-exchange`).
- **MailKit SMTP + Mailpit:** Console fallback for local/CI and real SMTP via `MailKit` for Mailpit or cloud providers.
- **Defense in Depth:** `FluentValidation` action filter, IP `RateLimiter` (`429`), RBAC role seeding (`Admin`/`User`), `.NET 10` `IExceptionHandler` (`ProblemDetails`), and integration tests via `WebApplicationFactory<Program>`.

---

## Endpoints Overview

| Method | Route | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Create user, assign `User` role & send confirmation email |
| `GET` | `/api/auth/confirm-email` | Confirm account email |
| `POST` | `/api/auth/login` | Authenticate (supports TOTP 2FA) & issue tokens / cookie |
| `POST` | `/api/auth/refresh-token` | Rotate refresh token (JSON body or `HttpOnly` cookie) |
| `POST` | `/api/auth/logout` | Revoke active refresh token & clear cookie |
| `POST` | `/api/auth/forgot-password` | Dispatch password reset token (enumeration-safe) |
| `POST` | `/api/auth/reset-password` | Reset password & revoke all active sessions |
| `GET` | `/api/auth/me` | Return authenticated user claims |
| `POST` | `/api/auth/2fa/setup` | Generate TOTP shared key & `otpauth://` URI |
| `POST` | `/api/auth/2fa/enable` | Verify 6-digit TOTP & generate recovery codes |
| `POST` | `/api/auth/2fa/disable` | Disable 2FA (requires valid TOTP code) |
| `GET` | `/api/auth/external-login/{provider}` | Start Google or GitHub OAuth 2.0 login |
| `GET` | `/api/auth/external-callback` | Handle OAuth callback & issue 60s exchange code |
| `POST` | `/api/auth/external-exchange` | Exchange 60s code for JWT + Refresh Token |
| `GET` | `/api/admin/users` | Admin-only user listing (`[Authorize(Roles = "Admin")]`) |
| `POST` | `/api/admin/promote` | Promote user to `Admin` role |
| `GET` | `/health` | Database connectivity health check |

## Run Integration Tests

```bash
dotnet test JwtAuthenticator.Tests/JwtAuthenticator.Tests.csproj
```