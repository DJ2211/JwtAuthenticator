using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Server;

namespace JwtAuthenticator.McpServer.Tools;

[McpServerToolType]
public static class StarterTools
{
    private static readonly JsonSerializerOptions JsonWriteOptions = new() { WriteIndented = true };

    // =========================================================================
    // TOOL 1: SCAFFOLD A NEW AUTH STARTER PROJECT (V2)
    // =========================================================================
    [McpServerTool]
    [Description("Scaffolds a production-ready .NET 10 JWT Authenticator starter project (with Dockerfile & docker-compose.yml) configured for a chosen database, cookie mode, and frontend origins.")]
    public static string ScaffoldAuthProject(
        [Description("Absolute path where the new project folder should be created.")] string targetDirectory,
        [Description("Project and root namespace name (e.g., MyShopAuth).")] string projectName,
        [Description("Database provider: sqlite, postgres, or sqlserver.")] string databaseProvider = "sqlite",
        [Description("Optional database connection string. Leave empty for default local template.")] string? connectionString = null,
        [Description("Comma-separated frontend origins for CORS (e.g., http://localhost:5173,http://localhost:3000).")] string frontendOrigins = "http://localhost:5173,http://localhost:3000",
        [Description("Set true to store Refresh Tokens in HttpOnly cookies instead of JSON responses (recommended for web SPAs).")] bool useHttpOnlyCookies = false)
    {
        var templateDir = ResolveTemplateDirectory();
        if (templateDir is null)
        {
            return "ERROR: Could not locate the bundled or local JwtAuthenticator template directory.";
        }

        var normalizedProvider = databaseProvider.Trim().ToLowerInvariant();
        if (normalizedProvider is not ("sqlite" or "postgres" or "sqlserver"))
        {
            return "ERROR: databaseProvider must be one of: sqlite, postgres, sqlserver.";
        }

        var destination = Path.Combine(targetDirectory, projectName);
        if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
        {
            return $"ERROR: Destination '{destination}' already exists and is not empty.";
        }

        // 1. Copy starter files (skipping build artifacts, local DBs, and SQLite migrations if switching DB)
        var skipMigrations = normalizedProvider != "sqlite";
        CopyTemplateDirectory(templateDir, destination, skipMigrations);

        // 2. Rename .csproj and namespaces if projectName differs from JwtAuthenticator
        if (!string.Equals(projectName, "JwtAuthenticator", StringComparison.Ordinal))
        {
            var oldCsproj = Path.Combine(destination, "JwtAuthenticator.csproj");
            var newCsproj = Path.Combine(destination, $"{projectName}.csproj");
            if (File.Exists(oldCsproj))
            {
                File.Move(oldCsproj, newCsproj);
            }

            foreach (var csFile in Directory.GetFiles(destination, "*.cs", SearchOption.AllDirectories))
            {
                var content = File.ReadAllText(csFile).Replace("JwtAuthenticator", projectName);
                File.WriteAllText(csFile, content, Encoding.UTF8);
            }

            var dockerfilePath = Path.Combine(destination, "Dockerfile");
            if (File.Exists(dockerfilePath))
            {
                var dockerContent = File.ReadAllText(dockerfilePath).Replace("JwtAuthenticator", projectName);
                File.WriteAllText(dockerfilePath, dockerContent, Encoding.UTF8);
            }
        }

        // 3. Copy docker-compose.yml alongside the new project
        var composeSource = ResolveComposeTemplatePath();
        if (composeSource is not null)
        {
            var composeText = File.ReadAllText(composeSource)
                .Replace("context: ./JwtAuthenticator", "context: .")
                .Replace("jwtauth-", $"{projectName.ToLowerInvariant()}-");
            File.WriteAllText(Path.Combine(destination, "docker-compose.yml"), composeText, Encoding.UTF8);
        }

        // 4. Generate fresh cryptographic JWT key and update appsettings.json
        var appSettingsPath = Path.Combine(destination, "appsettings.json");
        if (File.Exists(appSettingsPath))
        {
            var root = JsonNode.Parse(File.ReadAllText(appSettingsPath))?.AsObject() ?? new JsonObject();
            root["DatabaseProvider"] = normalizedProvider;

            if (!string.IsNullOrWhiteSpace(connectionString))
            {
                var connStrings = root["ConnectionStrings"]?.AsObject() ?? new JsonObject();
                var key = normalizedProvider switch
                {
                    "postgres" => "Postgres",
                    "sqlserver" => "SqlServer",
                    _ => "Sqlite"
                };
                connStrings[key] = connectionString;
                root["ConnectionStrings"] = connStrings;
            }

            var jwtSettings = root["JwtSettings"]?.AsObject() ?? new JsonObject();
            jwtSettings["SecretKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
            jwtSettings["Issuer"] = projectName;
            jwtSettings["Audience"] = $"{projectName}Client";
            jwtSettings["UseHttpOnlyRefreshCookie"] = useHttpOnlyCookies;
            root["JwtSettings"] = jwtSettings;

            var originsArray = new JsonArray();
            foreach (var origin in frontendOrigins.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                originsArray.Add(origin);
            }
            root["CorsSettings"] = new JsonObject { ["AllowedOrigins"] = originsArray };

            File.WriteAllText(appSettingsPath, root.ToJsonString(JsonWriteOptions), Encoding.UTF8);
        }

        var migrationNote = skipMigrations
            ? "\nNext step: Run `dotnet ef migrations add InitialCreate` and `dotnet ef database update` for your target database."
            : "\nNext step: Run `dotnet ef database update` and `dotnet run` (or `docker compose up --build`).";

        return $"Successfully scaffolded '{projectName}' at '{destination}' (DB: '{normalizedProvider}', HttpOnlyCookies: {useHttpOnlyCookies}) with a fresh cryptographic JWT key.{migrationNote}";
    }

    // =========================================================================
    // TOOL 2: GENERATE FRONTEND AUTH CLIENT (JSON OR HTTPONLY COOKIE MODE)
    // =========================================================================
    [McpServerTool]
    [Description("Generates a frontend auth client with Single-Flight Refresh Mutex for React/Axios, Next.js/Fetch, or Angular (supports both JSON and HttpOnly Cookie modes).")]
    public static string GenerateFrontendAuthClient(
        [Description("Target frontend style: react-axios, nextjs-fetch, or angular.")] string framework,
        [Description("Backend API base URL (e.g., https://localhost:7001).")] string apiBaseUrl = "https://localhost:7001",
        [Description("Set true if backend has UseHttpOnlyRefreshCookie enabled.")] bool useHttpOnlyCookies = false,
        [Description("Optional file path to write the generated client directly to disk.")] string? outputPath = null)
    {
        var code = framework.Trim().ToLowerInvariant() switch
        {
            "react-axios" => BuildReactAxiosClient(apiBaseUrl, useHttpOnlyCookies),
            "nextjs-fetch" => BuildNextFetchClient(apiBaseUrl, useHttpOnlyCookies),
            "angular" => BuildAngularClient(apiBaseUrl, useHttpOnlyCookies),
            _ => string.Empty
        };

        if (string.IsNullOrWhiteSpace(code))
        {
            return "ERROR: Unsupported framework. Choose one of: react-axios, nextjs-fetch, angular.";
        }

        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            var dir = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(outputPath, code, Encoding.UTF8);
            return $"Generated '{framework}' auth client (HttpOnlyCookies={useHttpOnlyCookies}) and saved it to '{outputPath}'.";
        }

        return code;
    }

    // =========================================================================
    // TOOL 3: AUDIT SECURITY CONFIGURATION (V2)
    // =========================================================================
    [McpServerTool]
    [Description("Audits an appsettings.json file for JWT, CORS, Cookie, Email, OAuth, and seeded admin security issues.")]
    public static string AuditSecurityConfig(
        [Description("Full path to the appsettings.json file to audit.")] string appsettingsPath)
    {
        if (!File.Exists(appsettingsPath)) return $"ERROR: File not found at '{appsettingsPath}'.";

        var root = JsonNode.Parse(File.ReadAllText(appsettingsPath));
        if (root is null) return "ERROR: Invalid JSON.";

        var findings = new List<string>();

        var secret = root["JwtSettings"]?["SecretKey"]?.GetValue<string>() ?? "";
        if (secret.Length < 32)
            findings.Add("[CRITICAL] JwtSettings:SecretKey is shorter than 32 characters.");
        if (secret.Contains("super_secret_key", StringComparison.OrdinalIgnoreCase) || secret.Contains("REPLACE_WITH", StringComparison.OrdinalIgnoreCase))
            findings.Add("[CRITICAL] JwtSettings:SecretKey is still using a default placeholder!");

        var expiryMins = root["JwtSettings"]?["AccessTokenExpiryMinutes"]?.GetValue<int?>() ?? 15;
        if (expiryMins > 60)
            findings.Add($"[WARNING] AccessTokenExpiryMinutes is {expiryMins} minutes. Recommended: 5 to 15 minutes.");

        var origins = root["CorsSettings"]?["AllowedOrigins"]?.AsArray();
        if (origins is not null && origins.Any(o => o?.GetValue<string>() == "*"))
            findings.Add("[CRITICAL] CorsSettings:AllowedOrigins contains wildcard '*'. This breaks AllowCredentials() and weakens security.");

        var adminPass = root["SeedAdmin"]?["Password"]?.GetValue<string>();
        if (adminPass == "Admin@Password123!")
            findings.Add("[WARNING] SeedAdmin:Password is using the default dev password. Override via environment variables/secrets in production.");

        var googleSecret = root["Authentication"]?["Google"]?["ClientSecret"]?.GetValue<string>();
        var githubSecret = root["Authentication"]?["GitHub"]?["ClientSecret"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(googleSecret) || !string.IsNullOrWhiteSpace(githubSecret))
            findings.Add("[INFO] OAuth ClientSecret detected in appsettings.json. Ensure secrets are moved to User Secrets or env vars before committing to Git.");

        return findings.Count == 0
            ? "PASS: No security configuration issues detected in appsettings.json."
            : "Security Audit Findings:\n- " + string.Join("\n- ", findings);
    }

    // =========================================================================
    // TOOL 4: SWITCH DATABASE PROVIDER
    // =========================================================================
    [McpServerTool]
    [Description("Updates DatabaseProvider and ConnectionStrings in an existing JwtAuthenticator appsettings.json.")]
    public static string SwitchDatabaseProvider(
        [Description("Full path to appsettings.json.")] string appsettingsPath,
        [Description("Target provider: sqlite, postgres, or sqlserver.")] string provider,
        [Description("New connection string for the chosen provider.")] string connectionString)
    {
        if (!File.Exists(appsettingsPath)) return $"ERROR: File not found at '{appsettingsPath}'.";

        var normalized = provider.Trim().ToLowerInvariant();
        if (normalized is not ("sqlite" or "postgres" or "sqlserver"))
            return "ERROR: provider must be sqlite, postgres, or sqlserver.";

        var root = JsonNode.Parse(File.ReadAllText(appsettingsPath))?.AsObject() ?? new JsonObject();
        root["DatabaseProvider"] = normalized;

        var connStrings = root["ConnectionStrings"]?.AsObject() ?? new JsonObject();
        var connKey = normalized switch
        {
            "postgres" => "Postgres",
            "sqlserver" => "SqlServer",
            _ => "Sqlite"
        };
        connStrings[connKey] = connectionString;
        root["ConnectionStrings"] = connStrings;

        File.WriteAllText(appsettingsPath, root.ToJsonString(JsonWriteOptions), Encoding.UTF8);
        return $"Updated '{appsettingsPath}' to use '{normalized}'.";
    }

    // =========================================================================
    // TOOL 5: CONFIGURE EMAIL PROVIDER (SMTP / CONSOLE)
    // =========================================================================
    [McpServerTool]
    [Description("Configures EmailSettings in appsettings.json for console logging or SMTP (Mailpit, Resend, SendGrid, Gmail).")]
    public static string ConfigureEmailProvider(
        [Description("Full path to appsettings.json.")] string appsettingsPath,
        [Description("Provider mode: console or smtp.")] string provider,
        [Description("SMTP host (e.g., localhost, mailpit, smtp.resend.com).")] string smtpHost = "localhost",
        [Description("SMTP port (e.g., 1025 for Mailpit, 587 for TLS SMTP).")] int smtpPort = 1025,
        [Description("Sender email address.")] string fromEmail = "noreply@example.com",
        [Description("Enable TLS/SSL (false for local Mailpit, true for cloud SMTP).")] bool useSsl = false)
    {
        if (!File.Exists(appsettingsPath)) return $"ERROR: File not found at '{appsettingsPath}'.";

        var normalized = provider.Trim().ToLowerInvariant();
        if (normalized is not ("console" or "smtp"))
            return "ERROR: provider must be 'console' or 'smtp'.";

        var root = JsonNode.Parse(File.ReadAllText(appsettingsPath))?.AsObject() ?? new JsonObject();
        var emailSettings = root["EmailSettings"]?.AsObject() ?? new JsonObject();

        emailSettings["Provider"] = normalized;
        emailSettings["SmtpHost"] = smtpHost;
        emailSettings["SmtpPort"] = smtpPort;
        emailSettings["FromEmail"] = fromEmail;
        emailSettings["UseSsl"] = useSsl;
        root["EmailSettings"] = emailSettings;

        File.WriteAllText(appsettingsPath, root.ToJsonString(JsonWriteOptions), Encoding.UTF8);
        return $"Configured EmailSettings in '{appsettingsPath}' to '{normalized}' ({smtpHost}:{smtpPort}, UseSsl={useSsl}). Set Username/Password via environment variables if using cloud SMTP.";
    }

    // =========================================================================
    // TOOL 6: CONFIGURE EXTERNAL OAUTH PROVIDER (GOOGLE / GITHUB)
    // =========================================================================
    [McpServerTool]
    [Description("Configures Google or GitHub OAuth 2.0 ClientId and ClientSecret in appsettings.json.")]
    public static string ConfigureOAuthProvider(
        [Description("Full path to appsettings.json.")] string appsettingsPath,
        [Description("OAuth provider: google or github.")] string provider,
        [Description("OAuth Client ID.")] string clientId,
        [Description("OAuth Client Secret (for local dev; use env vars in production).")] string clientSecret)
    {
        if (!File.Exists(appsettingsPath)) return $"ERROR: File not found at '{appsettingsPath}'.";

        var sectionKey = provider.Trim().ToLowerInvariant() switch
        {
            "google" => "Google",
            "github" => "GitHub",
            _ => null
        };

        if (sectionKey is null) return "ERROR: provider must be 'google' or 'github'.";

        var root = JsonNode.Parse(File.ReadAllText(appsettingsPath))?.AsObject() ?? new JsonObject();
        var auth = root["Authentication"]?.AsObject() ?? new JsonObject();

        auth[sectionKey] = new JsonObject
        {
            ["ClientId"] = clientId,
            ["ClientSecret"] = clientSecret
        };
        root["Authentication"] = auth;

        File.WriteAllText(appsettingsPath, root.ToJsonString(JsonWriteOptions), Encoding.UTF8);
        return $"Configured {sectionKey} OAuth in '{appsettingsPath}'. Remember to set Authentication__{sectionKey}__ClientSecret via env vars in production!";
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================
    private static string? ResolveTemplateDirectory()
    {
        var envPath = Environment.GetEnvironmentVariable("JWT_STARTER_TEMPLATE_PATH");
        if (!string.IsNullOrWhiteSpace(envPath) && Directory.Exists(envPath)) return envPath;

        // 1. Check bundled Templates folder inside Global .NET Tool / build output
        var bundled = Path.Combine(AppContext.BaseDirectory, "Templates", "JwtAuthenticator");
        if (File.Exists(Path.Combine(bundled, "JwtAuthenticator.csproj"))) return bundled;

        // 2. Fallback: walk up parent directories in local repo
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "JwtAuthenticator");
            if (File.Exists(Path.Combine(candidate, "JwtAuthenticator.csproj"))) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    private static string? ResolveComposeTemplatePath()
    {
        var bundled = Path.Combine(AppContext.BaseDirectory, "Templates", "docker-compose.yml");
        if (File.Exists(bundled)) return bundled;

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "docker-compose.yml");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }

    private static void CopyTemplateDirectory(string sourceDir, string destDir, bool skipMigrations)
    {
        Directory.CreateDirectory(destDir);
        string[] excludedDirs = skipMigrations ? ["bin", "obj", ".vs", ".git", "Migrations"] : ["bin", "obj", ".vs", ".git"];

        foreach (var file in Directory.GetFiles(sourceDir))
        {
            var fileName = Path.GetFileName(file);
            if (fileName.EndsWith(".db", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".db-shm", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".db-wal", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".user", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            File.Copy(file, Path.Combine(destDir, fileName), overwrite: true);
        }

        foreach (var subDir in Directory.GetDirectories(sourceDir))
        {
            var dirName = Path.GetFileName(subDir);
            if (excludedDirs.Contains(dirName, StringComparer.OrdinalIgnoreCase)) continue;
            CopyTemplateDirectory(subDir, Path.Combine(destDir, dirName), skipMigrations);
        }
    }

    private static string BuildReactAxiosClient(string baseUrl, bool useCookies) => useCookies
        ? $$"""
            import axios from 'axios';

            export const apiClient = axios.create({
              baseURL: '{{baseUrl}}/api',
              headers: { 'Content-Type': 'application/json' },
              withCredentials: true, // Sends HttpOnly refreshToken cookie automatically
            });

            let refreshPromise: Promise<string> | null = null;

            apiClient.interceptors.request.use((config) => {
              const token = sessionStorage.getItem('accessToken');
              if (token) config.headers.Authorization = `Bearer ${token}`;
              return config;
            });

            apiClient.interceptors.response.use(
              (res) => res,
              async (error) => {
                const original = error.config;
                if (error.response?.status === 401 && !original._retry) {
                  original._retry = true;
                  if (!refreshPromise) {
                    refreshPromise = axios
                      .post('{{baseUrl}}/api/auth/refresh-token', {}, { withCredentials: true })
                      .then((res) => {
                        sessionStorage.setItem('accessToken', res.data.accessToken);
                        return res.data.accessToken as string;
                      })
                      .finally(() => { refreshPromise = null; });
                  }
                  const newAccessToken = await refreshPromise;
                  original.headers.Authorization = `Bearer ${newAccessToken}`;
                  return apiClient(original);
                }
                return Promise.reject(error);
              }
            );
            """
        : $$"""
            import axios from 'axios';

            export const apiClient = axios.create({
              baseURL: '{{baseUrl}}/api',
              headers: { 'Content-Type': 'application/json' },
            });

            let refreshPromise: Promise<string> | null = null;

            apiClient.interceptors.request.use((config) => {
              const token = localStorage.getItem('accessToken');
              if (token) config.headers.Authorization = `Bearer ${token}`;
              return config;
            });

            apiClient.interceptors.response.use(
              (res) => res,
              async (error) => {
                const original = error.config;
                if (error.response?.status === 401 && !original._retry) {
                  original._retry = true;
                  const refreshToken = localStorage.getItem('refreshToken');
                  if (!refreshToken) return Promise.reject(error);
                  if (!refreshPromise) {
                    refreshPromise = axios
                      .post('{{baseUrl}}/api/auth/refresh-token', { refreshToken })
                      .then((res) => {
                        localStorage.setItem('accessToken', res.data.accessToken);
                        localStorage.setItem('refreshToken', res.data.refreshToken);
                        return res.data.accessToken as string;
                      })
                      .finally(() => { refreshPromise = null; });
                  }
                  const newAccessToken = await refreshPromise;
                  original.headers.Authorization = `Bearer ${newAccessToken}`;
                  return apiClient(original);
                }
                return Promise.reject(error);
              }
            );
            """;

    private static string BuildNextFetchClient(string baseUrl, bool useCookies) => $$"""
        const BASE_URL = '{{baseUrl}}/api';
        let refreshPromise: Promise<string | null> | null = null;

        async function refreshAccessToken(): Promise<string | null> {
          if (!refreshPromise) {
            const refreshToken = {{(useCookies ? "null" : "localStorage.getItem('refreshToken')")}};
            {{(useCookies ? "" : "if (!refreshToken) return null;")}}
            refreshPromise = fetch(`${BASE_URL}/auth/refresh-token`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              {{(useCookies ? "credentials: 'include'," : "body: JSON.stringify({ refreshToken }),")}}
            })
              .then(async (res) => {
                if (!res.ok) return null;
                const data = await res.json();
                localStorage.setItem('accessToken', data.accessToken);
                {{(useCookies ? "" : "localStorage.setItem('refreshToken', data.refreshToken);")}}
                return data.accessToken as string;
              })
              .finally(() => { refreshPromise = null; });
          }
          return refreshPromise;
        }

        export async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
          const token = localStorage.getItem('accessToken');
          const headers = new Headers(init.headers);
          headers.set('Content-Type', 'application/json');
          if (token) headers.set('Authorization', `Bearer ${token}`);

          const opts: RequestInit = { ...init, headers{{(useCookies ? ", credentials: 'include'" : "")}} };
          const res = await fetch(`${BASE_URL}${path}`, opts);
          if (res.status !== 401) return res;

          const freshToken = await refreshAccessToken();
          if (!freshToken) return res;

          headers.set('Authorization', `Bearer ${freshToken}`);
          return fetch(`${BASE_URL}${path}`, { ...opts, headers });
        }
        """;

    private static string BuildAngularClient(string baseUrl, bool useCookies) => $$"""
        import { HttpInterceptorFn } from '@angular/common/http';
        import { catchError, from, switchMap, throwError } from 'rxjs';

        let refreshInFlight: Promise<string> | null = null;

        export const jwtInterceptor: HttpInterceptorFn = (req, next) => {
          const token = localStorage.getItem('accessToken');
          const authedReq = req.clone({
            {{(useCookies ? "withCredentials: true," : "")}}
            ...(token ? { setHeaders: { Authorization: `Bearer ${token}` } } : {})
          });

          return next(authedReq).pipe(
            catchError((err) => {
              if (err.status !== 401) return throwError(() => err);
              const refreshToken = {{(useCookies ? "null" : "localStorage.getItem('refreshToken')")}};
              {{(useCookies ? "" : "if (!refreshToken) return throwError(() => err);")}}

              if (!refreshInFlight) {
                refreshInFlight = fetch('{{baseUrl}}/api/auth/refresh-token', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  {{(useCookies ? "credentials: 'include'," : "body: JSON.stringify({ refreshToken }),")}}
                })
                  .then((r) => r.json())
                  .then((data) => {
                    localStorage.setItem('accessToken', data.accessToken);
                    {{(useCookies ? "" : "localStorage.setItem('refreshToken', data.refreshToken);")}}
                    return data.accessToken as string;
                  })
                  .finally(() => { refreshInFlight = null; });
              }

              return from(refreshInFlight).pipe(
                switchMap((newToken) =>
                  next(req.clone({ {{(useCookies ? "withCredentials: true, " : "")}}setHeaders: { Authorization: `Bearer ${newToken}` } }))
                )
              );
            })
          );
        };
        """;
}