$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sdkDir = "C:\Program Files\Mantra\MFS100\Driver\MFS100Test"
$compiler = "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
$outDir = Join-Path $repoRoot "bin"

if (-not (Test-Path $compiler)) { throw " .NET Framework C# compiler not found: $compiler" }
if (-not (Test-Path (Join-Path $sdkDir "MANTRA.MFS100.dll"))) {
    throw "MFS100 SDK not found in $sdkDir"
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Build x86 because the installed MFS100 native DLLs are 32-bit.
& $compiler /nologo /target:exe /platform:x86 `
    /out:"$outDir\FingerprintService.exe" `
    /reference:"$sdkDir\MANTRA.MFS100.dll" `
    /reference:"$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\System.Security.dll" `
    "$repoRoot\src\MFS100Manager.cs" `
    "$repoRoot\src\FingerprintStorage.cs" `
    "$repoRoot\src\EnrollmentService.cs" `
    "$repoRoot\src\FingerprintConfiguration.cs" `
    "$repoRoot\src\VerificationService.cs" `
    "$repoRoot\src\Program.cs"

if ($LASTEXITCODE -ne 0) { throw "Compilation failed." }

# Copy runtime dependencies locally for DLL resolution. Do not commit these
# proprietary vendor binaries; .gitignore excludes the bin folder.
Copy-Item "$sdkDir\*.dll" $outDir -Force

Write-Host "Build successful: $outDir\FingerprintService.exe"
Write-Host "Run with: .\bin\FingerprintService.exe"
