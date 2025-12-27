# Usage: Run this script from the project root in PowerShell
# Output: dist/safeguard-extension.zip

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$src = Join-Path $root 'extension'
$dist = Join-Path $root 'dist'
$out = Join-Path $dist 'safeguard-extension.zip'

if (!(Test-Path $dist)) { New-Item -ItemType Directory -Path $dist | Out-Null }
if (Test-Path $out) { Remove-Item $out }

# Create a temporary staging directory to exclude dev/test files
$stage = Join-Path $dist 'stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Path $stage | Out-Null

# Copy files excluding dev/test and design sources
$excludeDirs = @('test','dev')
$excludeFiles = @('export.html','README.txt','icon.svg','STORE_LISTING.md','PRIVACY_POLICY.md','TERMS_OF_SERVICE.md')

Get-ChildItem -Path $src -Recurse | ForEach-Object {
  $rel = $_.FullName.Substring($src.Length).TrimStart('\','/')
  if ($_.PSIsContainer) {
    if ($excludeDirs -contains (Split-Path $rel -Leaf)) { return }
    $targetDir = Join-Path $stage $rel
    if (!(Test-Path $targetDir)) { New-Item -ItemType Directory -Path $targetDir | Out-Null }
  } else {
    if ($excludeDirs | ForEach-Object { $rel -like "*\$_*" }) { return }
    if ($excludeFiles -contains (Split-Path $rel -Leaf)) { return }
    $dest = Join-Path $stage $rel
    $destDir = Split-Path $dest -Parent
    if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir | Out-Null }
    Copy-Item $_.FullName $dest
  }
}

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $out -Force
Write-Host "Created package: $out"


