# Code Review Exercise: API Key Authentication Handler

## Overview

You're reviewing a pull request from Sam, a mid-level developer on the Identity team. The PR adds an API key authentication handler for Domain's developer portal. External developers wanted to use API keys to authenticate machine-to-machine requests to Domain's public APIs.

**Time Allocation:** 10-15 minutes for silent review, then 10-15 minutes for discussion

---

## Context

The Identity team maintains the authentication infrastructure for Domain's public API portal (developer.domain.com.au). Third-party developers register applications and receive API keys to call Domain APIs. This handler validates incoming API keys and establishes the caller's identity for downstream services.

**Tech Stack:** ASP.NET Core 8, Entity Framework Core, SQL Server

---

## PR Description (from Sam)

> **Title:** Add API key authentication handler for developer portal
>
> Hey team,
>
> This PR adds the API key authentication handler we discussed. Developers pass their API key in the `X-Api-Key` header, we validate it against the database and set up their claims for downstream authorization.
>
> I've tested it locally with a few sample keys and it works great. Ready for review!
>
> — Sam

---

## Your Task

Review this code as you would a real code review on your team. Consider:

1. **Correctness** — Does this work? Are there bugs?
2. **Security** — Is this safe for an authentication handler?
3. **Performance** — Will this perform under load?
4. **Production readiness** — What's missing?

**Take notes as you review. Then we'll discuss your findings.**

---

## Expected Load

- ~200 registered API clients
- ~500 requests/second at peak
- API keys are 64-character random hex strings

---

## Files to Review

1. `ApiKeyAuthenticationHandler.cs` — The authentication handler
2. `Program.cs` — Service registration and middleware

---

## File 1: ApiKeyAuthenticationHandler.cs

```csharp
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Domain.Identity.Auth;

public class ApiKeyAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IdentityDbContext _dbContext;
    private static readonly Dictionary<string, ApiClient> _cache = new();

    public ApiKeyAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IdentityDbContext dbContext) : base(options, logger, encoder)
    {
        _dbContext = dbContext;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var apiKey = Request.Headers["X-Api-Key"].ToString();

        if (apiKey == "")
            return AuthenticateResult.NoResult();

        // Check cache first for performance
        if (_cache.ContainsKey(apiKey))
        {
            var cachedClient = _cache[apiKey];
            return BuildResult(cachedClient, apiKey);
        }

        ApiClient client;
        try
        {
            client = _dbContext.ApiClients
                .FromSqlRaw($"SELECT * FROM ApiClients WHERE ApiKey = '{apiKey}' AND IsActive = 1")
                .FirstOrDefault();
        }
        catch (Exception)
        {
            return AuthenticateResult.Fail("Authentication service unavailable");
        }

        if (client == null)
        {
            Logger.LogWarning($"Failed auth attempt with key: {apiKey} from IP: {Request.HttpContext.Connection.RemoteIpAddress}");
            return AuthenticateResult.Fail($"Invalid API key: {apiKey}");
        }

        if (client.ExpiresAt < DateTime.Now)
            return AuthenticateResult.Fail("API key expired");

        // Update last used and add to cache
        client.LastUsedAt = DateTime.Now;
        _dbContext.SaveChanges();
        _cache[apiKey] = client;

        Logger.LogInformation($"Authenticated client {client.Name} with key {apiKey}");

        return BuildResult(client, apiKey);
    }

    private AuthenticateResult BuildResult(ApiClient client, string apiKey)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, client.Id.ToString()),
            new Claim("client_name", client.Name),
            new Claim("scopes", client.Scopes),
            new Claim("api_key", apiKey),
        };

        var identity = new ClaimsIdentity(claims, Scheme.Name);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);

        return AuthenticateResult.Success(ticket);
    }
}

public class ApiClient
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string ApiKey { get; set; }
    public string Scopes { get; set; }
    public string Secret { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? LastUsedAt { get; set; }
    public bool IsActive { get; set; }
    public bool IsRevoked { get; set; }
}
```

---

## File 2: Program.cs

```csharp
using Domain.Identity.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://0.0.0.0:80");

builder.Services.AddAuthentication("ApiKey")
    .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>("ApiKey", null);

builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseSqlServer("Server=identity-db.internal;Database=IdentityPlatform;User Id=identity_svc;Password=Id3nt1ty!Pr0d;TrustServerCertificate=True"));

builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```
