# Builds aws/.build/ for the SAM template (Linux wheels, since Lambda runs on Linux).
# Run from the repo root:  powershell -ExecutionPolicy Bypass -File aws\build.ps1
$ErrorActionPreference = "Stop"
$aws   = $PSScriptRoot
$root  = Split-Path -Parent $aws
$build = Join-Path $aws ".build"

if (Test-Path $build) { Remove-Item $build -Recurse -Force }
New-Item -ItemType Directory $build | Out-Null

# Use the repo's 3.12 venv when present; the flags below force Linux (manylinux) wheels either way.
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPy) { $py = $venvPy; $pyArgs = @() } else { $py = "py"; $pyArgs = @("-3.12") }

& $py @pyArgs -m pip install -r (Join-Path $aws "lambda\requirements.txt") --target $build `
  --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 --only-binary=:all: --upgrade
if ($LASTEXITCODE -ne 0) { throw "pip install of Linux wheels failed" }

Copy-Item -Recurse (Join-Path $root "backend") (Join-Path $build "backend")
Copy-Item (Join-Path $aws "lambda\handler.py") $build

# Never ship tests, caches or local secrets.
Remove-Item -Recurse -Force (Join-Path $build "backend\tests") -ErrorAction SilentlyContinue
Remove-Item -Force (Join-Path $build "backend\.env") -ErrorAction SilentlyContinue
Get-ChildItem $build -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force

Write-Host "Built $build"
