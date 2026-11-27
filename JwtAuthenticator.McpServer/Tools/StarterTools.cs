using ModelContextProtocol.Server;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace JwtAuthenticator.McpServer.Tools
{
    [McpServerToolType]
    public static class StarterTools
    {
        private static readonly JsonSerializerOptions JsonWriteOptions = new() { WriteIndented = true };

        // =========================================================================
        // TOOL 1: SCAFFOLD A NEW AUTH STARTER PROJECT
        // =========================================================================
        [McpServerTool]
        [Description("Scaffolds a prodution-ready .Net10 JWT Authenticator starter project configured for a chosen database and frontend origins.")]
        public static string ScaffoldAuthProject(
            [Description("Absolute path where the new project folder should be created.")] string targetDirectory,
            [Description("Project and root namespace name (e.g., MyShopAuth).")] string projectName,
            [Description("Database provider: sqlite, postgres, or sqlserver.")] string databaseProvider = "sqlite",
            [Description("Optional database connection string. Leave empty for defualt local template.")] string? connectionString = null,
            [Description("Comma-separated frontend origins for CORS (e.g., http://localhost:5173,http://localhost:3000).")] string frontendOrigins = "http://localhost:5173,http://localhost:3000"
            )
        {
            var templateDir = ResolveTemplateDirectory();
            if (templateDir is null)
            {
                return "ERROR: Coult not locate the JwtAuthenticator template directory. See the JWT_STARTER_TEMPLATE_PATH environment variable.";
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

            // 1. Copy starter files (skipping build artifacts, local DBs, and provider-specific migrations if switching DB)
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
                    var content = File.ReadAllText(csFile);
                    content = content.Replace("JwtAuthenticator", projectName);
                    File.WriteAllText(csFile, content, Encoding.UTF8);
                }
            }

            // 3. Generate a fresh 64-byte cryptographic JWT secret and configure appsettings.json
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
            : "\nNext step: Run `dotnet ef database update` and `dotnet run`.";
            return $"Successfully scaffolded '{projectName}' at '{destination}' with provider '{normalizedProvider}' and a fresh cryptographic JWT key.{migrationNote}";
        }

        // =========================================================================
        // TOOL 2: GENERATE FRONTEND AUTH CLIENT (WITH REFRESH MUTEX)
        // =========================================================================
        [McpServerTool]
        [Description("Generate a frontend auth client (with automatic Single-Fligh Refresh Mutex) for React/Axios, Next.js/Fetch, or Angular.")]
        public static string GenerateFrontendAuthClient(
            [Description("Target frontend style: react-axios, nextjs-fetch, or angular.")] string framework,
            [Description("Backend API base URL (e.g., https://localhost:7001).")] string apiBaseUrl = "https://localhost:7001",
            [Description("Optional file path to write the generated client directly to disk.")] string? outputPath = null
            )
        {
            var code = framework.Trim().ToLowerInvariant() switch
            {
                "react-axios" => BuildReactAxiosClient(apiBaseUrl),
                "nextjs-fetch" => BuildNextFetchClient(apiBaseUrl),
                "angular" => BuildAngularClient(apiBaseUrl),
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
                return $"Generated '{framework}' auth client and saved it to '{outputPath}'.";
            }

            return code;
        }

        // =========================================================================
        // TOOL 3: AUDIT SECURITY CONFIGURATION
        // =========================================================================
        [McpServerTool]
        [Description("Audits an appsettings.json file for JWT, CORS, and seeded admin security misconfigurations.")]
        public static string AuditSecurityConfig([Description("Full path to the appsettings.json file to audit.")] string appsettingsPath)
        {
            if (!File.Exists(appsettingsPath))
            {
                return $"ERROR: File not found at '{appsettingsPath}'.";
            }

            var root = JsonNode.Parse(File.ReadAllText(appsettingsPath));
            if (root is null) return "ERROR: Invalid JSON.";

            var findings = new List<string>();

            // 1. Check JWT SecretKey
            var secret = root["JwtSettings"]?["SecretKey"]?.GetValue<string>() ?? "";

            if (secret.Length < 32)
                findings.Add("[CRITICAL] JwtSettings:SecretKey is shorter than 32 characters (unsafe for HMAC-SHA256).");
            if (secret.Contains("super_secret_key", StringComparison.OrdinalIgnoreCase) || secret.Contains("REPLACE_WITH", StringComparison.OrdinalIgnoreCase))
                findings.Add("[CRITICAL] JwtSettings:SecretKey is still using a default/template placeholder!");

            // 2. Check Access Token lifetime
            var expiryMins = root["JwtSettings"]?["AccessTokenExpiryMinutes"]?.GetValue<int?>() ?? 15;
            if (expiryMins > 60)
                findings.Add($"[WARNING] AccessTokenExpiryMinutes is {expiryMins} minutes. Recommended: 5 to 15 minutes.");

            // 3. Check CORS wildcard
            var origins = root["CorsSettings"]?["AllowedOrigins"]?.AsArray();
            if (origins is not null && origins.Any(o => o?.GetValue<string>() == "*"))
                findings.Add("[CRITICAL] CorsSettings:AllowedOrigins contains wildcard '*'. This fails with AllowCredentials() and weakens security.");

            // 4. Check Default SeedAdmin Password
            var adminPass = root["SeedAdmin"]?["Password"]?.GetValue<string>();
            if (adminPass == "Admin@Password123!")
                findings.Add("[WARNING] SeedAdmin:Password is using the default dev password. Remove or override via secrets in production.");

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
        // PRIVATE HELPERS
        // =========================================================================
        private static string? ResolveTemplateDirectory()
        {
            var envPath = Environment.GetEnvironmentVariable("JWT_STARTER_TEMPLATE_PATH");
            if (!string.IsNullOrWhiteSpace(envPath) && Directory.Exists(envPath)) return envPath;
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                var candidate = Path.Combine(dir.FullName, "JwtAuthenticator");
                if (File.Exists(Path.Combine(candidate, "JwtAuthenticator.csproj")))
                {
                    return candidate;
                }
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

        private static string BuildReactAxiosClient(string baseUrl) => $$"""
            import axios from 'axios';
            export const apiClient = axios.create({
              baseURL: '{{baseUrl}}/api',
              headers: { 'Content-Type': 'application/json' },
            });
            // Single-Flight Refresh Mutex prevents parallel 401s from tripping Replay Attack Detection
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
        private static string BuildNextFetchClient(string baseUrl) => $$"""
            const BASE_URL = '{{baseUrl}}/api';
            let refreshPromise: Promise<string | null> | null = null;
            async function refreshAccessToken(): Promise<string | null> {
              if (!refreshPromise) {
                const refreshToken = localStorage.getItem('refreshToken');
                if (!refreshToken) return null;
                refreshPromise = fetch(`${BASE_URL}/auth/refresh-token`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ refreshToken }),
                })
                  .then(async (res) => {
                    if (!res.ok) return null;
                    const data = await res.json();
                    localStorage.setItem('accessToken', data.accessToken);
                    localStorage.setItem('refreshToken', data.refreshToken);
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
              const res = await fetch(`${BASE_URL}${path}`, { ...init, headers });
              if (res.status !== 401) return res;
              const freshToken = await refreshAccessToken();
              if (!freshToken) return res;
              headers.set('Authorization', `Bearer ${freshToken}`);
              return fetch(`${BASE_URL}${path}`, { ...init, headers });
            }
            """;
        private static string BuildAngularClient(string baseUrl) => $$"""
            import { HttpInterceptorFn } from '@angular/common/http';
            import { catchError, from, switchMap, throwError } from 'rxjs';
            let refreshInFlight: Promise<string> | null = null;
            export const jwtInterceptor: HttpInterceptorFn = (req, next) => {
              const token = localStorage.getItem('accessToken');
              const authedReq = token
                ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
                : req;
              return next(authedReq).pipe(
                catchError((err) => {
                  if (err.status !== 401) return throwError(() => err);
                  const refreshToken = localStorage.getItem('refreshToken');
                  if (!refreshToken) return throwError(() => err);
                  if (!refreshInFlight) {
                    refreshInFlight = fetch('{{baseUrl}}/api/auth/refresh-token', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ refreshToken }),
                    })
                      .then((r) => r.json())
                      .then((data) => {
                        localStorage.setItem('accessToken', data.accessToken);
                        localStorage.setItem('refreshToken', data.refreshToken);
                        return data.accessToken as string;
                      })
                      .finally(() => { refreshInFlight = null; });
                  }
                  return from(refreshInFlight).pipe(
                    switchMap((newToken) =>
                      next(req.clone({ setHeaders: { Authorization: `Bearer ${newToken}` } }))
                    )
                  );
                })
              );
            };
            """;
    }
}
