<#
.SYNOPSIS
  Downloads the Npcap SDK into vendor/npcap-sdk so the Rust `pcap` crate can link.

.DESCRIPTION
  The SDK only provides import libraries (wpcap.lib, Packet.lib) and headers
  used at build time. At runtime Fishe uses the Npcap driver installed on the
  machine (https://npcap.com). .cargo/config.toml (repo root) points
  LIBPCAP_LIBDIR at vendor/npcap-sdk/Lib/x64.

  The import libraries end up inside the Fishe binary, so they are checked
  against known SHA-256 hashes before they are installed: a different file
  behind the same URL stops the build instead of being linked in.

.PARAMETER Version
  SDK version to fetch from https://npcap.com/dist/. Default: 1.17.

.PARAMETER AllowUnverified
  Install a version this script has no hashes for (when trying a new SDK;
  add its hashes to $KnownHashes before relying on it).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/setup-npcap-sdk.ps1
#>
param(
    [string]$Version = "1.17",
    [switch]$Force,
    [switch]$AllowUnverified
)

$ErrorActionPreference = "Stop"

# SHA-256 of the files the linker reads, per SDK version.
$KnownHashes = @{
    "1.17" = @{
        "Lib\x64\wpcap.lib"  = "A99934FE9FA67FB72D538B480593EA8D2540DA0D9979C0C27B3D5848F2173F16"
        "Lib\x64\Packet.lib" = "E96E0D001C2C25B542EA57B1E3B26431FFFB94841E6C4CB5D3FA827AAF128DDC"
    }
}
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "vendor\npcap-sdk"
$lib = Join-Path $dest "Lib\x64\wpcap.lib"

if ((Test-Path $lib) -and -not $Force) {
    Write-Host "Npcap SDK already present at $dest (use -Force to re-download)."
    exit 0
}

$url = "https://npcap.com/dist/npcap-sdk-$Version.zip"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("npcap-sdk-" + [guid]::NewGuid() + ".zip")

$expected = $KnownHashes[$Version]
if (-not $expected -and -not $AllowUnverified) {
    throw "No known hashes for Npcap SDK $Version. Add them to `$KnownHashes, or pass -AllowUnverified."
}

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $tmp -UseBasicParsing

# Unpack next to the destination and check there: nothing unverified ever
# sits where the build looks.
$staging = "$dest.new"
if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
New-Item -ItemType Directory -Force $staging | Out-Null
try {
    Expand-Archive -Path $tmp -DestinationPath $staging
    if ($expected) {
        foreach ($file in $expected.Keys) {
            $path = Join-Path $staging $file
            if (-not (Test-Path $path)) { throw "$file is missing from the SDK archive" }
            $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            if ($actual -ne $expected[$file]) {
                throw "$file does not match the known Npcap SDK $Version (SHA-256 $actual, expected $($expected[$file])). Not installed."
            }
        }
        Write-Host "Import libraries match the known SDK $Version."
    } else {
        Write-Warning "Npcap SDK $Version installed without a hash check (-AllowUnverified)."
    }
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Move-Item $staging $dest
} finally {
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if (Test-Path $staging) { Remove-Item -Recurse -Force $staging }
}

if (-not (Test-Path $lib)) { throw "wpcap.lib not found after extraction: $lib" }
Write-Host "Npcap SDK $Version installed to $dest"
