#!/usr/bin/env bash
# find_apps_by_signature.sh — Group installed APKs by signing certificate (SHA-256),
# or filter to a specific target signature.
#
# Usage:
#   ./find_apps_by_signature.sh                 # group every package by SHA-256
#   ./find_apps_by_signature.sh -t <SHA256>     # only print packages matching target
#   ./find_apps_by_signature.sh -s <serial>     # pick a specific device
#   ./find_apps_by_signature.sh -u              # also include user (3rd-party) packages only
#   ./find_apps_by_signature.sh -h              # help
#
# Tested on macOS (zsh/bash 3.2) and Linux (bash 4+). Requires: adb, keytool (JDK).

set -u
set -o pipefail

TARGET=""
SERIAL=""
USER_ONLY=0
SHOW_HELP=0

while getopts "t:s:uh" opt; do
    case "$opt" in
        t) TARGET="$(echo "$OPTARG" | tr 'a-f' 'A-F' | tr -d ' :')" ;;
        s) SERIAL="$OPTARG" ;;
        u) USER_ONLY=1 ;;
        h) SHOW_HELP=1 ;;
        *) SHOW_HELP=1 ;;
    esac
done

if [ "$SHOW_HELP" = "1" ]; then
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi

# --- Sanity checks --------------------------------------------------------
command -v adb >/dev/null 2>&1 || { echo "ERROR: adb not on PATH"; exit 1; }

# Prefer apksigner (handles APK Signature Scheme v1/v2/v3/v4). keytool only
# reads v1 (JAR) signatures, so most modern APKs come back empty with it.
# Always pick the NEWEST installed build-tools/apksigner — older versions
# (≤30.0.3) refuse to print certs when v1 manifest is missing, even with
# --min-sdk-version. Newer apksigner + --min-sdk-version 28 handles v2-only.
APKSIGNER_BIN=""
for SDK_ROOT in "${ANDROID_HOME:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [ -z "$SDK_ROOT" ] && continue
    [ -d "$SDK_ROOT/build-tools" ] || continue
    LATEST_BT=$(ls -1 "$SDK_ROOT/build-tools" 2>/dev/null | sort -V | tail -n 1)
    if [ -n "$LATEST_BT" ] && [ -x "$SDK_ROOT/build-tools/$LATEST_BT/apksigner" ]; then
        APKSIGNER_BIN="$SDK_ROOT/build-tools/$LATEST_BT/apksigner"
        break
    fi
done
# Fall back to PATH apksigner only if no SDK install was found
if [ -z "$APKSIGNER_BIN" ] && command -v apksigner >/dev/null 2>&1; then
    APKSIGNER_BIN=$(command -v apksigner)
fi

USE_APKSIGNER=0
if [ -n "$APKSIGNER_BIN" ]; then
    USE_APKSIGNER=1
else
    command -v keytool >/dev/null 2>&1 || { echo "ERROR: neither apksigner nor keytool on PATH. Install Android build-tools or JDK."; exit 1; }
    echo "WARN: apksigner not found; falling back to keytool. Modern v2/v3-only APKs will appear unsigned."
fi

ADB=(adb)
[ -n "$SERIAL" ] && ADB+=(-s "$SERIAL")

DEVICE_COUNT=$("${ADB[@]}" devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')
if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo "ERROR: no device found. Connect a device with USB debugging enabled."
    exit 1
fi
if [ "$DEVICE_COUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    echo "ERROR: multiple devices attached. Pass -s <serial> to pick one. Devices:"
    "${ADB[@]}" devices
    exit 1
fi

TMPDIR_=$(mktemp -d -t apksig.XXXXXX)
trap 'rm -rf "$TMPDIR_"' EXIT

echo "Listing installed packages..."
PM_FLAGS=""
[ "$USER_ONLY" = "1" ] && PM_FLAGS="-3"

# Read packages into a plain array (bash 3.2 friendly: no read -d '')
PACKAGES=()
while IFS= read -r line; do
    line="${line%$'\r'}"           # strip CR from adb on Windows-CRLF input
    line="${line#package:}"
    [ -n "$line" ] && PACKAGES+=("$line")
done < <("${ADB[@]}" shell pm list packages $PM_FLAGS)

TOTAL=${#PACKAGES[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "No packages found."
    exit 1
fi

if [ -n "$TARGET" ]; then
    echo "Scanning $TOTAL packages for SHA-256 = $TARGET"
else
    echo "Scanning $TOTAL packages and grouping by SHA-256..."
fi

# Map of fingerprint -> "pkg1 pkg2 ..." (newline-delimited file in TMPDIR_)
GROUPS_FILE="$TMPDIR_/groups.tsv"   # format: "<sig>\t<pkg>"
: >"$GROUPS_FILE"

i=0
for PKG in "${PACKAGES[@]}"; do
    i=$((i + 1))
    # Pretty progress on the same line (carriage return)
    printf "\r[%3d/%3d] %-60s" "$i" "$TOTAL" "$PKG"

    # Get the FIRST APK path (base.apk) — splits share the same signing cert
    APK_PATH=$("${ADB[@]}" shell pm path "$PKG" 2>/dev/null | head -n 1 | tr -d '\r')
    APK_PATH="${APK_PATH#package:}"
    [ -z "$APK_PATH" ] && continue

    LOCAL_APK="$TMPDIR_/$PKG.apk"
    "${ADB[@]}" pull "$APK_PATH" "$LOCAL_APK" >/dev/null 2>&1 || continue

    if [ "$USE_APKSIGNER" = "1" ]; then
        # apksigner output formats we need to handle:
        #   Signer #1 certificate SHA-256 digest: f0fd6c5b...                              (single signer)
        #   Signer (minSdkVersion=33, maxSdkVersion=...) certificate SHA-256 digest: ...   (v3 with rotation - first line is newest cert)
        #   Source Stamp Signer certificate SHA-256 digest: ...                            (skip - Play Store anti-tamper)
        # Match anything starting with "Signer " (excludes "Source Stamp Signer"). Take the FIRST match
        # (apksigner lists newest cert first). Output is lowercase hex no colons; normalize to UPPER:UPPER.
        # --min-sdk-version 28 skips v1-manifest verification — without it apksigner bails on v2/v3-only APKs.
        RAW=$("$APKSIGNER_BIN" verify --min-sdk-version 28 --print-certs "$LOCAL_APK" 2>/dev/null \
                | awk '/^Signer .*certificate SHA-256 digest:/ {print $NF; exit}')
        if [ -n "$RAW" ]; then
            SIG=$(echo "$RAW" | tr 'a-f' 'A-F' | sed 's/../&:/g; s/:$//')
        else
            SIG=""
        fi
    else
        # NOTE the trailing colon — without it we also match "SHA256withRSA" and break
        SIG=$(keytool -printcert -jarfile "$LOCAL_APK" 2>/dev/null \
                | awk '/SHA256:/ {print $2; exit}' \
                | tr 'a-f' 'A-F' | tr -d ' \r')
    fi

    rm -f "$LOCAL_APK"

    [ -z "$SIG" ] && continue

    if [ -n "$TARGET" ]; then
        # Compare colon-stripped so the user can pass either format ("49:30:..." or "493028...")
        if [ "${SIG//:/}" = "$TARGET" ]; then
            printf "\r%-72s\r" ""   # clear progress line
            echo "MATCH  $PKG"
        fi
    else
        printf '%s\t%s\n' "$SIG" "$PKG" >>"$GROUPS_FILE"
    fi
done
printf "\r%-72s\r" ""   # clear progress line

# --- Output ---------------------------------------------------------------
if [ -n "$TARGET" ]; then
    echo "Done. (Scanned $TOTAL packages.)"
    exit 0
fi

echo
echo "Developer groups (signature -> packages):"
echo "------------------------------------------"
# Group by signature, sorted by group size descending
sort "$GROUPS_FILE" | awk -F'\t' '
    { sig=$1; pkg=$2; pkgs[sig]=pkgs[sig] ? pkgs[sig] "\n  " pkg : "  " pkg; count[sig]++ }
    END {
        for (s in count) printf "%d\t%s\n", count[s], s
    }' | sort -rn | while IFS=$'\t' read -r CNT SIG; do
        echo
        echo "[$CNT apps] $SIG"
        # Re-extract this group's packages
        awk -F'\t' -v s="$SIG" '$1==s {print "  "$2}' "$GROUPS_FILE" | sort
done
echo
echo "Done. (Scanned $TOTAL packages.)"
