<#
  Runs the identity service as a native Windows executable (dist\windows\Identity.Api.exe).

    ./scripts/run-windows.ps1            start it (builds the exe first if it is missing)
    ./scripts/run-windows.ps1 -Rebuild   publish a fresh exe first
    ./scripts/run-windows.ps1 -Port 5002 -DbPort 5433   use other ports if 5001 / 5432 are taken (e.g. by docker compose)

  What it does, in order:
    1. loads .env (create it with ./scripts/dev-secrets.sh) and maps it to the app's configuration
    2. starts a local PostgreSQL 16 container named identity-pg-local on localhost:$DbPort (default 5432) (needs Docker for that only)
    3. runs the exe on http://localhost:$Port (default 5001)

  Local development only: plain http and secrets from .env. The admin console is a website, not part of the exe:
    docker compose up -d --no-deps --build admin-console      # then open http://localhost:4200
#>
param([switch]$Rebuild, [int]$Port = 5001, [int]$DbPort = 5432)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$exe = Join-Path $root "dist\windows\Identity.Api.exe"
if ($Rebuild -or -not (Test-Path $exe)) {
    Write-Host "Publishing the executable..."
    dotnet publish src/Identity.Api/Identity.Api.csproj -c Release -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o dist/windows | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }
}

# 1. .env -> variables
if (-not (Test-Path .env)) { throw ".env not found. Run ./scripts/dev-secrets.sh first." }
$cfg = @{}
Get-Content .env | Where-Object { $_ -match '^\s*[A-Za-z_][A-Za-z0-9_]*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    $cfg[$k.Trim()] = $v
}
foreach ($required in "IDENTITY_DB_PASSWORD", "SIGNING_PFX", "SIGNING_PFX_PASSWORD", "TOKEN_ENCRYPTION_KEY", "MFA_ENCRYPTION_KEY") {
    if (-not $cfg.ContainsKey($required)) { throw ".env is missing $required" }
}

# 2. PostgreSQL in Docker
$name = "identity-pg-local"
$running = docker ps --filter "name=^$name$" --format "{{.Names}}" 2>$null
if (-not $running) {
    docker rm -f $name 2>$null | Out-Null
    Write-Host "Starting PostgreSQL ($name) on localhost:$DbPort..."
    docker run -d --name $name -p "${DbPort}:5432" `
        -e POSTGRES_DB=identity -e POSTGRES_USER=identity -e "POSTGRES_PASSWORD=$($cfg.IDENTITY_DB_PASSWORD)" `
        postgres:16-alpine | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not start PostgreSQL. Is Docker running, and is port $DbPort free?" }
}
Write-Host -NoNewline "Waiting for PostgreSQL"
for ($i = 0; $i -lt 60; $i++) {
    docker exec $name pg_isready -U identity -d identity 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { break }
    Write-Host -NoNewline "."; Start-Sleep -Seconds 1
}
Write-Host " ready"

# 3. configuration for the exe (same keys docker-compose uses)
$env:ASPNETCORE_URLS = "http://localhost:$Port"
$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ConnectionStrings__Identity = "Host=localhost;Port=$DbPort;Database=identity;Username=identity;Password=$($cfg.IDENTITY_DB_PASSWORD)"
$env:Server__Issuer = "http://localhost:$Port/"
$env:Server__RequireHttps = "false"
$env:Cors__AllowedOrigins__0 = "http://localhost:4200"
$env:Cors__AllowedOrigins__1 = "http://127.0.0.1:53682"          # the desktop admin tool's loopback redirect (see docs)
$env:OAuthClients__0__ClientId = "admin-console"
$env:OAuthClients__0__RedirectUris__0 = "http://localhost:4200/auth/callback"
$env:OAuthClients__1__ClientId = "admin-desktop"                   # IdentityAdmin.exe (admin-desktop/), public client + PKCE
$env:OAuthClients__1__DisplayName = "Admin desktop tool"
$env:OAuthClients__1__RedirectUris__0 = "http://127.0.0.1:53682/callback"
$env:Signing__Certificates__0__Pfx = $cfg.SIGNING_PFX
$env:Signing__Certificates__0__Password = $cfg.SIGNING_PFX_PASSWORD
$env:Signing__EncryptionKey = $cfg.TOKEN_ENCRYPTION_KEY
$env:Mfa__EncryptionKey = $cfg.MFA_ENCRYPTION_KEY
if ($cfg.ContainsKey("BOOTSTRAP_ADMIN_EMAIL")) {
    $env:Bootstrap__AdminEmail = $cfg.BOOTSTRAP_ADMIN_EMAIL
    $env:Bootstrap__AdminPassword = $cfg.BOOTSTRAP_ADMIN_PASSWORD
}

Write-Host "Identity service: http://localhost:$Port   (Ctrl+C to stop)"
& $exe
