<#
.SYNOPSIS
    Publishes Anti-Google as a self-contained single-file win-x64 executable.

.DESCRIPTION
    Produces release/win-x64/AntiGoogle.exe with the .NET runtime bundled, so it runs on a machine
    with no .NET installed. That matters for this app in particular: someone reaching for a
    de-Googling tool should not have to install a runtime first.

    Trimming is deliberately OFF. WPF resolves styles, templates and converters through reflection
    over XAML, and the trimmer cannot see those references — a trimmed build loses control templates
    at runtime with no compile-time warning. The size cost is worth a window that actually renders.

.PARAMETER Configuration
    Build configuration. Release by default.

.PARAMETER SkipTests
    Skip the test run. Do not use this for a build you intend to ship.

.EXAMPLE
    ./publish-windows.ps1
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

$outDir = Join-Path $root 'release/win-x64'

Write-Host ''
Write-Host 'Anti-Google — publish' -ForegroundColor Cyan
Write-Host ('=' * 60)

if (-not $SkipTests) {
    Write-Host 'Running tests...' -ForegroundColor Cyan
    dotnet test AntiGoogle.sln --configuration $Configuration --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed — refusing to publish.' }

    # Same assertions, no signed test host required. Both are run because a runner that discovers
    # nothing reports success just as loudly as one that passes.
    dotnet run --project tests/AntiGoogle.Verify --configuration $Configuration --nologo
    if ($LASTEXITCODE -ne 0) { throw 'Standalone verification failed — refusing to publish.' }
}

Write-Host 'Regenerating the icon from Logo.xaml...' -ForegroundColor Cyan
dotnet run --project tools/AntiGoogle.IconGen --configuration $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw 'Icon generation failed.' }

if (Test-Path $outDir) { Remove-Item $outDir -Recurse -Force }

Write-Host 'Publishing...' -ForegroundColor Cyan
dotnet publish src/AntiGoogle.App/AntiGoogle.App.csproj `
    --configuration $Configuration `
    --runtime win-x64 `
    --self-contained true `
    --output $outDir `
    --nologo `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:PublishTrimmed=false `
    -p:DebugType=none `
    -p:SatelliteResourceLanguages=en

if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }

$exe = Join-Path $outDir 'AntiGoogle.exe'
if (-not (Test-Path $exe)) { throw "Expected $exe but it was not produced." }

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()

Write-Host ''
Write-Host ('=' * 60)
Write-Host "  Output : $exe"
Write-Host "  Size   : $size MB"
Write-Host "  SHA256 : $hash"
Write-Host ''
Write-Host '  Unsigned. Windows SmartScreen will warn on first run, and Smart App' -ForegroundColor Yellow
Write-Host '  Control may block it outright. That is expected for an unsigned build.' -ForegroundColor Yellow
Write-Host ''
