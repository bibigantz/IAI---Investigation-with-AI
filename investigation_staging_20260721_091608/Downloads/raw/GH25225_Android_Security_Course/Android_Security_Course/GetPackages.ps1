<#
.SYNOPSIS
    Group installed APKs on a connected Android device by signing certificate (SHA-256),
    or filter to a specific target signature.

.DESCRIPTION
    Pulls each package's base.apk from the device and runs `apksigner verify
    --print-certs` to extract the SHA-256 fingerprint of the signing certificate.
    Falls back to `keytool` if apksigner is not available. Split APKs share the
    parent's cert, so only base.apk is checked.

.PARAMETER TargetSignature
    Optional SHA-256 to match against. If omitted, all packages are listed grouped
    by certificate (the more interesting "see who shares a developer" view).

.PARAMETER Serial
    adb device serial. Required if more than one device is attached.

.PARAMETER UserOnly
    Restrict to user-installed (3rd-party) packages only.

.EXAMPLE
    .\GetPackages.ps1
    .\GetPackages.ps1 -TargetSignature "49:30:28:..."
    .\GetPackages.ps1 -Serial R58R404WTXY
    .\GetPackages.ps1 -UserOnly
#>
[CmdletBinding()]
param(
    [string]$TargetSignature = "",
    [string]$Serial = "",
    [switch]$UserOnly
)

$ErrorActionPreference = "Stop"

# --- Sanity checks --------------------------------------------------------
# Ensure JAVA_HOME is set (apksigner needs it). Try Android Studio's bundled JBR/JRE.
if (-not $env:JAVA_HOME) {
    foreach ($javaDir in @("$env:ProgramFiles\Android\Android Studio\jbr",
                           "$env:ProgramFiles\Android\Android Studio\jre")) {
        if (Test-Path "$javaDir\bin\java.exe") {
            $env:JAVA_HOME = $javaDir
            $env:PATH = "$javaDir\bin;$env:PATH"
            break
        }
    }
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    # Try common SDK location before giving up
    $sdkPlatformTools = "$env:LOCALAPPDATA\Android\Sdk\platform-tools"
    if (Test-Path "$sdkPlatformTools\adb.exe") {
        $env:PATH = "$sdkPlatformTools;$env:PATH"
    } else {
        Write-Error "adb not on PATH. Install Android platform-tools and add them to PATH."
        exit 1
    }
}

# Prefer apksigner (handles APK Signature Scheme v1/v2/v3/v4). keytool only
# reads v1 (JAR) signatures. Always pick the NEWEST installed apksigner —
# older versions (≤30.0.3) refuse to print certs when v1 manifest is missing.
$ApkSigner = $null
foreach ($root in @($env:ANDROID_HOME, "$env:LOCALAPPDATA\Android\sdk", "$env:USERPROFILE\AppData\Local\Android\sdk")) {
    # Use -ErrorAction SilentlyContinue so a stale ANDROID_HOME pointing at another
    # user's profile (Access Denied) doesn't kill the script — fall through to the next root.
    if ($root -and (Test-Path "$root\build-tools" -ErrorAction SilentlyContinue)) {
        # Sort by version (natural order), newest last
        $latest = Get-ChildItem "$root\build-tools" -Directory -ErrorAction SilentlyContinue |
            Sort-Object { [version]($_.Name -replace '[^0-9.].*$','0') } -ErrorAction SilentlyContinue |
            Select-Object -Last 1
        if ($latest) {
            $candidate = Join-Path $latest.FullName "apksigner.bat"
            if (Test-Path $candidate -ErrorAction SilentlyContinue) {
                $ApkSigner = $candidate
                break
            }
        }
    }
}
# Fall back to PATH apksigner only if no SDK install was found
if (-not $ApkSigner) {
    $cmd = Get-Command apksigner -ErrorAction SilentlyContinue
    if ($cmd) { $ApkSigner = $cmd.Source }
}

$KeytoolFallback = $false
$KeytoolAvailable = [bool](Get-Command keytool -ErrorAction SilentlyContinue)
if (-not $ApkSigner) {
    if ($KeytoolAvailable) {
        Write-Warning "apksigner not found; falling back to keytool. Modern v2/v3-only APKs will appear unsigned."
        $KeytoolFallback = $true
    } else {
        Write-Error "Neither apksigner nor keytool found on PATH. Install Android build-tools or JDK."
        exit 1
    }
}

$AdbArgs = @()
if ($Serial) { $AdbArgs += @("-s", $Serial) }

$devices = & adb devices | Select-Object -Skip 1 |
    Where-Object { $_ -match "\bdevice$" }
if ($devices.Count -eq 0) {
    Write-Error "No device found. Connect a device with USB debugging enabled."
    exit 1
}
if ($devices.Count -gt 1 -and -not $Serial) {
    Write-Host "Multiple devices attached. Pass -Serial <serial> to pick one:" -ForegroundColor Yellow
    & adb devices
    exit 1
}

# Normalize: strip whitespace AND colons so the user can paste either format
# ("49:30:28:..." or "493028204afeae...") and it'll still match.
$Target = ($TargetSignature -replace '[\s:]', '').ToUpper()

$TempDir = Join-Path $env:TEMP "apksig_$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $TempDir | Out-Null
try {
    # --- List packages ----------------------------------------------------
    Write-Host "Listing installed packages..."
    $pmFlags = @("shell", "pm", "list", "packages")
    if ($UserOnly) { $pmFlags += "-3" }
    $packages = & adb @AdbArgs @pmFlags |
        ForEach-Object { ($_ -replace 'package:', '').Trim() } |
        Where-Object { $_ -ne "" }

    $total = $packages.Count
    if ($total -eq 0) { Write-Error "No packages found."; exit 1 }

    if ($Target) {
        Write-Host "Scanning $total packages for SHA-256 = $Target"
    } else {
        Write-Host "Scanning $total packages and grouping by SHA-256..."
    }

    # --- Iterate ----------------------------------------------------------
    $groups = @{}   # sig -> List<string>
    $skipped = New-Object System.Collections.Generic.List[string]
    $fallbacks = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($pkg in $packages) {
        $i++
        Write-Progress -Activity "Reading APK signatures" -Status $pkg `
                       -PercentComplete (($i / $total) * 100)

        try {
            # First path is base.apk; splits share the same cert.
            # Force array, filter to lines we expect, take one, coerce to string.
            # Some system packages (dictionaries, billing stubs, shared libraries)
            # return zero or multi-line `pm path` output that broke the old
            # one-liner with "[System.Object[]] does not contain a method named 'Trim'".
            $pmLines = @(& adb @AdbArgs shell pm path $pkg 2>$null)
            $firstPkgLine = $pmLines | Where-Object { $_ -match '^package:' } | Select-Object -First 1
            if (-not $firstPkgLine) {
                $skipped.Add("$pkg (no base.apk path)") | Out-Null
                continue
            }
            $apkPath = ([string]$firstPkgLine -replace '^package:', '').Trim()
            if (-not $apkPath) {
                $skipped.Add("$pkg (empty path after parse)") | Out-Null
                continue
            }

            $local = Join-Path $TempDir "$pkg.apk"
            $ErrorActionPreference = "Continue"
            & adb @AdbArgs pull $apkPath $local *>$null
            $ErrorActionPreference = "Stop"
            if (-not (Test-Path $local)) {
                $skipped.Add("$pkg (pull failed: $apkPath)") | Out-Null
                continue
            }

            $sig = $null
            $usedKeytoolFallback = $false
            # Run apksigner and keytool in Continue mode so a non-zero exit
            # (e.g. "DOES NOT VERIFY") doesn't bubble up to the outer catch
            # before we get a chance to try the fallback.
            $ErrorActionPreference = "Continue"
            if (-not $KeytoolFallback) {
                # apksigner output formats we need to handle:
                #   Signer #1 certificate SHA-256 digest: f0fd6c5b...                              (build-tools <=36)
                #   Signer (minSdkVersion=33, maxSdkVersion=...) certificate SHA-256 digest: ...   (v3 rotation, build-tools <=36)
                #   V3.0 Signer: certificate SHA-256 digest: ...                                   (build-tools 37+)
                #   V2.0 Signer: certificate SHA-256 digest: ...                                   (build-tools 37+)
                #   Source Stamp Signer certificate SHA-256 digest: ...                            (skip - Play anti-tamper)
                # Match lines containing "Signer" + "certificate SHA-256 digest:" but NOT "Source Stamp".
                # Take the FIRST match (newest cert in v3 rotation).
                # Output is lowercase hex without colons; normalize to UPPER:UPPER:...
                # --min-sdk-version 28 skips v1-manifest verification (otherwise apksigner bails on v2/v3-only APKs).
                $line = & $ApkSigner verify --min-sdk-version 28 --print-certs $local 2>$null |
                        Select-String -Pattern 'Signer.*certificate SHA-256 digest:' |
                        Where-Object { $_.Line -notmatch 'Source Stamp' } |
                        Select-Object -First 1
                if ($line) {
                    $raw = ($line.Line -split 'digest:\s+', 2)[1].Trim()
                    if ($raw) {
                        $bytes = ($raw -split '(.{2})' | Where-Object { $_ })
                        $sig = ($bytes -join ':').ToUpper()
                    }
                }
            }

            # Per-package fallback: if apksigner rejected the APK ("DOES NOT VERIFY")
            # or simply didn't print a Signer line we recognise, try keytool.
            # Common reason on older Samsung A51 (Android 11) preinstalls:
            # apksigner refuses v1-only APKs whose CERT.SF claims a v2 signature
            # that was stripped during the build/OTA — keytool ignores v2 entirely
            # and reads the v1 cert just fine.
            if (-not $sig -and $KeytoolAvailable) {
                $line = & keytool -printcert -jarfile $local 2>$null |
                        Select-String -Pattern '^\s*SHA256:' |
                        Select-Object -First 1
                if ($line) {
                    $sig = (($line.Line -split ':\s+', 2)[1]).Trim().ToUpper()
                    $usedKeytoolFallback = $true
                }
            }
            $ErrorActionPreference = "Stop"

            Remove-Item $local -ErrorAction SilentlyContinue
            if (-not $sig) {
                $skipped.Add("$pkg (no signature extracted)") | Out-Null
                continue
            }
            if ($usedKeytoolFallback) {
                $fallbacks.Add($pkg) | Out-Null
            }

            if ($Target) {
                # Compare colon-stripped uppercase to handle either input format
                if (($sig -replace ':','') -eq $Target) {
                    Write-Host ("MATCH  {0}" -f $pkg) -ForegroundColor Green
                }
            } else {
                if (-not $groups.ContainsKey($sig)) {
                    $groups[$sig] = New-Object System.Collections.Generic.List[string]
                }
                $groups[$sig].Add($pkg)
            }
        } catch {
            # Don't let one bad APK kill the whole scan — log and move on.
            $ErrorActionPreference = "Stop"
            $skipped.Add("$pkg (error: $($_.Exception.Message))") | Out-Null
            continue
        }
    }
    Write-Progress -Activity "Reading APK signatures" -Completed

    # --- Output -----------------------------------------------------------
    if ($Target) {
        Write-Host "Done. (Scanned $total packages, skipped $($skipped.Count).)"
        if ($skipped.Count -gt 0) {
            Write-Host "Skipped packages:" -ForegroundColor DarkYellow
            $skipped | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
        }
        return
    }

    Write-Host ""
    Write-Host "Developer groups (signature -> packages):"
    Write-Host "------------------------------------------"
    $groups.GetEnumerator() |
        Sort-Object -Property { $_.Value.Count } -Descending |
        ForEach-Object {
            Write-Host ""
            Write-Host ("[{0} apps] {1}" -f $_.Value.Count, $_.Key) -ForegroundColor Cyan
            $_.Value | Sort-Object | ForEach-Object { Write-Host "  $_" }
        }
    Write-Host ""
    Write-Host "Done. (Scanned $total packages, skipped $($skipped.Count), keytool fallback used on $($fallbacks.Count).)"
    if ($fallbacks.Count -gt 0) {
        Write-Host "Packages where apksigner failed and keytool succeeded:" -ForegroundColor DarkCyan
        $fallbacks | Sort-Object | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkCyan }
    }
    if ($skipped.Count -gt 0) {
        Write-Host "Skipped packages:" -ForegroundColor DarkYellow
        $skipped | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    }
}
finally {
    Remove-Item -Recurse -Force $TempDir -ErrorAction SilentlyContinue
}
