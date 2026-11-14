# MFS100 Fingerprint Service (development integration)

This is the first local integration milestone for the HID biometric-authentication repository.

## Requirements

- Windows with the Mantra MFS100 driver and SDK test-app files installed.
- .NET Framework 4.x C# compiler.
- 32-bit process (x86). The installed MFS100 native DLL dependencies are x86.
- MFS100 connected by USB.

## Build

Open Windows PowerShell in this directory:

```powershell
.\build.ps1
```

The script references the SDK at:

`C:\Program Files\Mantra\MFS100\Driver\MFS100Test`

It copies runtime DLL dependencies into `bin/` for local execution. The `bin/` directory is ignored by Git. Do not commit Mantra DLLs or biometric data.

## Run

```powershell
.\bin\FingerprintService.exe
```

The console menu offers scanner connection check, enrollment, 1:1 verification,
and exit. Enrollment and verification call their services, which own scanner
operations and storage access. Verification displays the API status and score
for diagnostics; with the default unconfigured threshold it always reports
`INDETERMINATE` and makes no authentication decision.

## Current limitations

- `EnrollmentService` provides local enrollment logic; the console entry point
  remains an SDK capture/comparison demo and does not invoke enrollment.
- No fingerprint verification workflow is implemented yet.
- No HTTP endpoint or AWS integration yet; the team's backend request contract must be agreed first.
- No liveness / presentation-attack detection is claimed.
- This is a development integration utility, not production-ready biometric storage.

## Secure local storage (Phase 2)

`FingerprintStorage` stores only DPAPI-protected ISO template bytes in
`<repository>/data/fingerprints/` by default. Set
`HID_BIOMETRIC_FINGERPRINT_DIR` to use a different directory. The storage API
accepts an ISO byte array, encrypts it with Windows DPAPI
(`DataProtectionScope.CurrentUser`) and purpose/user-specific optional entropy,
and never writes the plaintext template or extra metadata to disk. DPAPI binds
decryption to the current Windows user context; moving the data to another
Windows account or device needs a separate recovery strategy.

The service restricts the storage directory and record ACLs to the current
Windows user where the platform permits it. Records are written to a temporary
file in the same directory and moved atomically; an existing enrollment is not
overwritten. Missing records and records that are corrupted or cannot be
decrypted are returned as safe storage errors. User IDs are restricted to
letters, digits, underscores and hyphens before they are used as filenames.

The root `.gitignore` excludes `/data/` to prevent accidental Git tracking.
`.gitignore` is only a Git safeguard; it does not encrypt files or control who
can access them. Do not place real biometric records, test fingerprint samples,
SDK DLLs or build outputs in commits.

## Secure enrollment (Phase 3)

`EnrollmentService.Enroll(userId)` validates the user ID before touching storage
or the scanner, rejects existing records, initializes and checks the MFS100,
captures through the existing `MFS100Manager`, validates the capture result and
ISO template, then delegates encryption and persistence to `FingerprintStorage`.
The service always disposes the scanner device and clears its temporary ISO
array where practical. Its result reports status, user ID, capture quality,
NFIQ, scanner status code, UTC timestamp, and a safe error message when relevant.
The capture-device interface permits isolated tests without a physical scanner.

`EnrollmentService` does not make authentication decisions or apply a match
threshold. Real enrollment still requires an explicit operator action and a
connected scanner; automated checks use synthetic bytes only.

## 1:1 verification (Phase 4)

`VerificationService.Verify(userId)` loads and decrypts only that user's
enrollment, captures a fresh ISO template, and compares it with the existing
`MatchISO` API. It returns the API code and score for diagnostics, along with
capture quality/NFIQ and a UTC timestamp. It does not perform identification
across users.

The default `FingerprintConfiguration` has no threshold, so even a successful
comparison returns `Indeterminate`. A threshold can be supplied with an
explicit validation flag; configured but unvalidated values also always return
`Indeterminate`. `Verified` and `NotVerified` are produced only when a threshold
is explicitly marked validated. That flag requires external calibration
evidence; no threshold is supplied or calibrated by this project.

## Security

Never commit fingerprint templates, fingerprint images, SDK binaries, credentials, or user biometric data. Use consented test participants. Keep biometric templates local and protected; share only the minimum verification outcome required by the backend.
