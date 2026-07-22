import os
import sys
import json
import shutil
import glob
import subprocess
import string
import ctypes
import csv
import io
import hashlib
from datetime import datetime

# --- Configuration & Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
STAGING_ROOT = os.path.join(BASE_DIR, f"investigation_staging_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

EXTRA_CATEGORIES = ["ProgramDataList", "AlternateDataStreams", "VSS_Shadows", "SysinternalsAutoruns"]

# Hash algorithm used to verify every file copy (integrity / chain-of-custody).
# SHA-256 is the forensic standard; change here if a different algorithm is required.
HASH_ALGORITHM = "sha256"

# --- Global Execution Tracker ---
# "Collection"       -> raw file gathering results, per artifact category
# "Parsing"          -> metadata/parsed output results, per tool
# "HashVerification" -> summary + failure list for the before/after hash checks
#                        done on every single file this script copies
# "General"          -> everything else (staging setup, VSS, ADS scan, etc.)
execution_report = {
    "Collection": {},
    "Parsing": {},
    "HashVerification": {
        "algorithm": HASH_ALGORITHM,
        "total_files": 0,
        "verified": 0,
        "mismatched": 0,
        "hash_errors": 0,
        "failures": []   # every non-verified copy, with full exception/reason detail
    },
    "General": {
        "Successes": [],
        "Warnings_Skipped": [],
        "Errors": []
    }
}

# Full per-file audit trail (every file copied, verified or not). Written out
# as hash_manifest.csv at the end of the run for chain-of-custody documentation.
hash_manifest_entries = []


def log_success(msg):
    print(f"  [+] {msg}")
    execution_report["General"]["Successes"].append(msg)


def log_warning(msg):
    print(f"  [*] [WARNING] {msg}")
    execution_report["General"]["Warnings_Skipped"].append(msg)


def log_error(msg, e=None):
    error_text = f"{msg} | Exception: {str(e)}" if e else msg
    print(f"  [-] [ERROR] {error_text}")
    execution_report["General"]["Errors"].append(error_text)


# --- Load artifact target paths from external JSON config ---
def resolve_config_path():
    # Allow passing a custom config path as the first CLI arg
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        return sys.argv[1]
    candidates = [
        os.path.join(BASE_DIR, "collector_paths.json"),
        os.path.join(os.getcwd(), "collector_paths.json"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]  # doesn't exist; caller will report the error


def load_artifact_targets(config_path):
    if not os.path.exists(config_path):
        log_error(f"Config file not found: {config_path}. No standard artifacts will be collected.")
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log_error(f"Malformed JSON in config file: {config_path}", e)
        return {}
    except Exception as e:
        log_error(f"Failed to read config file: {config_path}", e)
        return {}

    if not isinstance(data, dict):
        log_error(f"Config file {config_path} must contain a JSON object of category -> [patterns].")
        return {}

    clean = {}
    for category, patterns in data.items():
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            log_warning(f"Skipping invalid category '{category}' in config (expected a list of path strings).")
            continue
        clean[category] = patterns

    log_success(f"Loaded {len(clean)} artifact categories from {config_path}")
    return clean


def get_available_drives():
    drives = []
    for letter in string.ascii_uppercase:
        if os.path.exists(f"{letter}:\\"):
            drives.append(f"{letter}:\\")
    return drives


def select_drive():
    drives = get_available_drives()
    if not drives:
        print("[-] No drives detected. Exiting.")
        sys.exit(1)

    print("\n[+] Available Drives Detected:")
    for i, drive in enumerate(drives):
        print(f"  [{i}] {drive}")

    while True:
        try:
            choice = int(input("\nSelect the number of the external drive to investigate: "))
            if 0 <= choice < len(drives):
                return drives[choice]
            else:
                print("[-] Invalid selection. Try again.")
        except ValueError:
            print("[-] Please enter a valid number.")


def setup_staging_env(categories):
    print(f"\n[+] Initializing Staging Directory at: {STAGING_ROOT}")
    try:
        for category in categories:
            os.makedirs(os.path.join(STAGING_ROOT, category, "raw"), exist_ok=True)
            os.makedirs(os.path.join(STAGING_ROOT, category, "metadata"), exist_ok=True)
        log_success("Staging environment created successfully.")
    except Exception as e:
        log_error("Failed to create complete staging environment", e)


def _username_prefix(path_str):
    """If path contains a Users\\<name>\\... segment, return '<name>_' else ''"""
    parts = path_str.split(os.sep)
    if "Users" in parts:
        try:
            idx = parts.index("Users")
            return f"{parts[idx + 1]}_"
        except IndexError:
            pass
    return ""


def compute_file_hash(path, algorithm=HASH_ALGORITHM, chunk_size=4 * 1024 * 1024):
    """
    Compute the hash of a file, reading it in chunks (safe for large evidence
    files like registry hives, .evtx logs, or Amcache.hve without loading the
    whole file into memory).

    Raises whatever exception occurs (file vanished, permission denied, I/O
    error, etc.) — callers are expected to catch it so the failure can be
    recorded in the report rather than crashing the run.
    """
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def copy_file_verified(src, dest_file, algorithm=HASH_ALGORITHM):
    """
    Copies ONE file and cryptographically verifies the copy is byte-for-byte
    identical to the source. This is how "hash check before and after" is
    implemented:

      1. Hash the SOURCE file BEFORE copying.
      2. Copy the file (shutil.copy2 — preserves timestamps/metadata).
      3. Hash the DESTINATION file AFTER copying.
      4. Compare the two hashes.
         - Match    -> copy is verified complete and uncorrupted.
         - Mismatch -> copy is corrupt/incomplete/changed mid-copy; the bad
                       destination file is deleted so it can never be
                       mistaken for valid evidence.

    Returns a result dict (never raises):
        {
          "success":    bool,        # the copy operation itself didn't raise
          "verified":   bool,        # True only if src_hash == dest_hash
          "src_hash":   str | None,
          "dest_hash":  str | None,
          "size_bytes": int | None,
          "error":      str | None,  # human-readable reason when not verified
        }

    Known limitation (documented, not silently hidden): if the source file is
    modified by the OS between step 1 and step 2 (e.g. a live/in-use file),
    the hashes can legitimately differ even though nothing is "wrong" with
    the copy mechanism itself — this is still reported as a mismatch, since
    the collector cannot distinguish that case from real corruption.
    """
    result = {
        "success": False,
        "verified": False,
        "src_hash": None,
        "dest_hash": None,
        "size_bytes": None,
        "error": None,
    }

    # Step 1: hash source BEFORE copying
    try:
        result["src_hash"] = compute_file_hash(src, algorithm)
    except Exception as e:
        result["error"] = f"Failed to hash source before copy: {e}"
        return result

    # Step 2: copy
    try:
        shutil.copy2(src, dest_file)
        result["success"] = True
    except PermissionError as e:
        result["error"] = f"Permission denied during copy (file likely locked/in-use): {e}"
        return result
    except Exception as e:
        result["error"] = f"Copy failed: {e}"
        return result

    # Step 3: hash destination AFTER copying
    try:
        result["dest_hash"] = compute_file_hash(dest_file, algorithm)
        result["size_bytes"] = os.path.getsize(dest_file)
    except Exception as e:
        result["error"] = f"Failed to hash destination after copy: {e}"
        return result

    # Step 4: compare
    if result["src_hash"] == result["dest_hash"]:
        result["verified"] = True
    else:
        result["error"] = "Hash mismatch after copy — destination file is corrupt/incomplete"
        try:
            os.remove(dest_file)
            result["error"] += " (corrupted copy removed)"
        except Exception as cleanup_e:
            result["error"] += f" (could NOT remove corrupted copy: {cleanup_e})"

    return result


def record_manifest_entry(category, src, dest_file, verify_result):
    """
    Logs the outcome of one verified copy to both:
      - hash_manifest_entries (full audit trail -> hash_manifest.csv)
      - execution_report["HashVerification"] (summary counts + failure detail)
    Also emits console log lines so failures are visible immediately, not
    only at the very end of the run.
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "category": category,
        "source_path": src,
        "dest_path": dest_file,
        "algorithm": HASH_ALGORITHM,
        "source_hash": verify_result["src_hash"],
        "dest_hash": verify_result["dest_hash"],
        "size_bytes": verify_result["size_bytes"],
        "verified": verify_result["verified"],
        "error": verify_result["error"],
    }
    hash_manifest_entries.append(entry)

    hv = execution_report["HashVerification"]
    hv["total_files"] += 1

    if verify_result["verified"]:
        hv["verified"] += 1
        log_success(f"Collected & hash-verified -> {os.path.basename(dest_file)} "
                    f"({HASH_ALGORITHM}={verify_result['dest_hash'][:12]}...)")
    else:
        if verify_result["src_hash"] is not None and verify_result["dest_hash"] is not None:
            hv["mismatched"] += 1
        else:
            hv["hash_errors"] += 1
        hv["failures"].append(entry)
        log_error(f"Hash verification FAILED for {src} -> {dest_file} | {verify_result['error']}")


def copy_preserving_context(src, dest_dir, category="Unknown"):
    """
    Copy a single file WITH hash verification (before/after) and record the
    outcome in the manifest/report. Returns True only if the copy completed
    AND the hash comparison confirmed the destination is identical to the
    source. A copy that "succeeds" at the OS level but fails verification is
    treated as a FAILURE here.
    """
    if not os.path.isfile(src):
        return False
    filename = _username_prefix(src) + os.path.basename(src)
    dest_file = os.path.join(dest_dir, filename)

    result = copy_file_verified(src, dest_file)
    record_manifest_entry(category, src, dest_file, result)
    return result["verified"]


def copy_matched_path(src, dest_dir, category="Unknown"):
    """
    Handles a single glob match, which may be a file OR a directory.
    Directories are walked recursively so nested files aren't silently skipped
    (this was the main cause of missing artifacts under Downloads, Temp,
    JumpLists, WER ReportArchive, RecycleBin, etc.)
    Every individual file copy — whether the match itself was a file, or a
    file found while walking a matched directory — is hash verified
    before/after via copy_file_verified().
    Returns (copied_and_verified_count, failed_count).
    """
    if os.path.isfile(src):
        ok = copy_preserving_context(src, dest_dir, category)
        return (1, 0) if ok else (0, 1)

    if os.path.isdir(src):
        copied = 0
        failed = 0
        prefix = _username_prefix(src)
        base_name = prefix + os.path.basename(src.rstrip("\\/"))
        sub_dest_root = os.path.join(dest_dir, base_name)

        for root, _, files in os.walk(src):
            rel = os.path.relpath(root, src)
            target_root = sub_dest_root if rel == "." else os.path.join(sub_dest_root, rel)
            try:
                os.makedirs(target_root, exist_ok=True)
            except Exception as e:
                log_error(f"Could not create directory {target_root}", e)
                failed += len(files)
                continue
            for fname in files:
                full_src = os.path.join(root, fname)
                dest_file = os.path.join(target_root, fname)
                result = copy_file_verified(full_src, dest_file)
                record_manifest_entry(category, full_src, dest_file, result)
                if result["verified"]:
                    copied += 1
                else:
                    failed += 1

        if copied:
            log_success(f"Collected directory -> {base_name} ({copied} files verified)")
        return (copied, failed)

    # Broken symlink / vanished between glob and copy / unsupported type
    return (0, 0)


def collect_standard_artifacts(target_drive, artifact_targets):
    print(f"\n[+] Starting Standard File Collection from {target_drive}...")
    for category, paths in artifact_targets.items():
        raw_dest = os.path.join(STAGING_ROOT, category, "raw")
        os.makedirs(raw_dest, exist_ok=True)
        print(f"[*] Collecting Category: {category}")

        cat_stats = {"files_found": 0, "files_copied": 0, "files_failed": 0, "patterns": {}}

        for path_pattern in paths:
            search_pattern = os.path.join(target_drive, path_pattern)
            try:
                matched = glob.glob(search_pattern, recursive=True)
            except Exception as e:
                log_error(f"Error evaluating path pattern {path_pattern}", e)
                cat_stats["patterns"][path_pattern] = {"error": str(e)}
                continue

            if not matched:
                log_warning(f"[{category}] No matches found for pattern: {path_pattern}")
                cat_stats["patterns"][path_pattern] = {"matched": 0}
                continue

            copied = 0
            failed = 0
            for match in matched:
                c, f = copy_matched_path(match, raw_dest, category)
                copied += c
                failed += f

            cat_stats["files_found"] += copied + failed
            cat_stats["files_copied"] += copied
            cat_stats["files_failed"] += failed
            cat_stats["patterns"][path_pattern] = {
                "matched_entries": len(matched),
                "files_copied": copied,
                "files_failed": failed
            }

        execution_report["Collection"][category] = cat_stats


def extract_sysinternals_autoruns(target_drive):
    print("\n[*] Starting Sysinternals Autoruns Deep Extraction...")
    autorunsc_tool = os.path.join(TOOLS_DIR, "autorunsc.exe")
    meta_dest = os.path.join(STAGING_ROOT, "SysinternalsAutoruns", "metadata")
    bin_dest = os.path.join(STAGING_ROOT, "SysinternalsAutoruns", "raw")
    os.makedirs(meta_dest, exist_ok=True)
    os.makedirs(bin_dest, exist_ok=True)

    if not os.path.exists(autorunsc_tool):
        log_warning("autorunsc.exe not found in tools folder. Skipping Sysinternals extraction.")
        execution_report["Parsing"]["SysinternalsAutoruns"] = {"status": "skipped", "detail": "autorunsc.exe missing"}
        return

    sys_root = os.path.join(target_drive, "Windows")
    if not os.path.exists(sys_root):
        log_error(f"Target Windows directory not found at {sys_root}. Cannot run offline Autoruns.")
        execution_report["Parsing"]["SysinternalsAutoruns"] = {"status": "failed", "detail": "Windows dir not found"}
        return

    profiles = [None]  # None = System Wide
    try:
        user_dirs = glob.glob(os.path.join(target_drive, "Users", "*"))
        for d in user_dirs:
            if os.path.isdir(d) and not d.lower().endswith("public"):
                profiles.append(d)
    except Exception as e:
        log_error("Failed to enumerate user profiles for Autoruns", e)

    profile_results = {}
    for profile in profiles:
        prof_name = "SystemWide" if profile is None else os.path.basename(profile)
        csv_file = os.path.join(meta_dest, f"autoruns_{prof_name}.csv")
        cmd = [autorunsc_tool, "-accepteula", "-a", "*", "-c", "-h", "-z", sys_root]
        if profile:
            cmd.append(profile)

        print(f"  [*] Scanning startup entries for: {prof_name}...")
        try:
            with open(csv_file, "w", encoding="utf-8") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL, timeout=120)

            if result.returncode != 0:
                log_error(f"autorunsc exited with code {result.returncode} for {prof_name}")
                profile_results[prof_name] = {"status": "failed", "detail": f"exit code {result.returncode}"}
                continue

            with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()

            if not content:
                log_warning(f"autorunsc produced no output for {prof_name}")
                profile_results[prof_name] = {"status": "warning", "detail": "empty output"}
                continue

            reader = csv.DictReader(io.StringIO(content))
            binaries_extracted = 0
            for row in reader:
                try:
                    image_path = row.get("Image Path", "")
                    if not image_path or image_path.lower() == "file not found":
                        continue

                    actual_path = ""
                    if image_path[1:3] == ":\\":
                        actual_path = target_drive + image_path[3:]
                    elif image_path.lower().startswith("\\systemroot\\"):
                        actual_path = os.path.join(sys_root, image_path[12:])
                    else:
                        actual_path = image_path

                    if os.path.exists(actual_path) and os.path.isfile(actual_path):
                        filename = os.path.basename(actual_path)
                        dest_file = os.path.join(bin_dest, f"{prof_name}_{filename}")
                        if not os.path.exists(dest_file):
                            verify_result = copy_file_verified(actual_path, dest_file)
                            record_manifest_entry("SysinternalsAutoruns", actual_path, dest_file, verify_result)
                            if verify_result["verified"]:
                                binaries_extracted += 1
                except Exception as loop_e:
                    log_error(f"Failed to process autorun row in {prof_name}", loop_e)

            log_success(f"Sysinternals extraction finished for {prof_name}")
            profile_results[prof_name] = {"status": "success", "binaries_extracted": binaries_extracted}
        except subprocess.TimeoutExpired:
            log_error(f"Autorunsc timed out for {prof_name}")
            profile_results[prof_name] = {"status": "failed", "detail": "timeout"}
        except Exception as e:
            log_error(f"Failed executing autorunsc on profile {prof_name}", e)
            profile_results[prof_name] = {"status": "failed", "detail": str(e)}

    execution_report["Parsing"]["SysinternalsAutoruns"] = profile_results


def extract_program_data_list(target_drive):
    print("\n[*] Enumerating ProgramData Directory Structure...")
    prog_data_path = os.path.join(target_drive, "ProgramData")
    meta_dir = os.path.join(STAGING_ROOT, "ProgramDataList", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    output_file = os.path.join(meta_dir, "installed_programs_list.txt")

    if not os.path.exists(prog_data_path):
        log_warning(f"ProgramData directory not found at {prog_data_path}.")
        return
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"--- Top Level Folders in ProgramData ({datetime.now()}) ---\n")
            for entry in os.scandir(prog_data_path):
                if entry.is_dir():
                    f.write(f"[DIR]  {entry.name}\n")
                elif entry.is_file():
                    f.write(f"[FILE] {entry.name} - Size: {entry.stat().st_size} bytes\n")
        log_success("Generated ProgramData listings manifest.")
    except Exception as e:
        log_error("Failed to generate ProgramData list", e)


def check_volume_shadow_copies(target_drive):
    print("\n[*] Auditing Volume Shadow Copies (VSS)...")
    drive_letter = target_drive.strip("\\")
    meta_dir = os.path.join(STAGING_ROOT, "VSS_Shadows", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    output_file = os.path.join(meta_dir, "vss_shadow_list.txt")
    try:
        result = subprocess.run(["vssadmin", "list", "shadows", f"/for={drive_letter}"],
                                 capture_output=True, text=True, shell=True, timeout=30)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- Errors Reported ---\n" + result.stderr)
        log_success("Staged VSS query information.")
    except Exception as e:
        log_error("Failed to query VSS copies", e)


def scan_for_alternate_data_streams(target_drive):
    print("\n[*] Scanning for Alternate Data Streams (ADS) in Temp and Downloads...")
    meta_dir = os.path.join(STAGING_ROOT, "AlternateDataStreams", "metadata")
    os.makedirs(meta_dir, exist_ok=True)
    output_file = os.path.join(meta_dir, "ads_scan_results.txt")
    target_dirs = [
        os.path.join(target_drive, "Users", "*", "Downloads"),
        os.path.join(target_drive, "Windows", "Temp")
    ]
    kernel32 = ctypes.windll.kernel32

    try:
        with open(output_file, "w", encoding="utf-8") as out_f:
            out_f.write("--- ALTERNATE DATA STREAM SCAN REPORT ---\n\n")
            for path_pattern in target_dirs:
                for directory in glob.glob(path_pattern):
                    for root, _, files in os.walk(directory):
                        for file in files:
                            full_path = os.path.join(root, file)

                            class WIN32_FIND_STREAM_DATA(ctypes.Structure):
                                _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 260)]

                            find_data = WIN32_FIND_STREAM_DATA()
                            handle = kernel32.FindFirstStreamW(ctypes.c_wchar_p(full_path), 0, ctypes.byref(find_data), 0)

                            if handle != -1:
                                try:
                                    while True:
                                        stream_name = find_data.cStreamName
                                        if stream_name and stream_name != "::$DATA":
                                            out_f.write(
                                                f"File: {full_path}\n  -> Stream Detected: {stream_name} "
                                                f"(Size: {find_data.StreamSize} bytes)\n\n"
                                            )
                                        if not kernel32.FindNextStreamW(handle, ctypes.byref(find_data)):
                                            break
                                finally:
                                    kernel32.FindClose(handle)
        log_success("ADS scan finished successfully.")
    except Exception as e:
        log_error("Failed during ADS scan", e)


def run_tool_parser(tool_name, tool_exe, raw_target, meta_dir, arg_tokens):
    """
    Runs an external parsing tool safely.

    FIX: arg_tokens is a LIST of argv tokens (e.g. ["-d", "{raw}", "--csv", "{meta}", "-q"]),
    NOT a single string that gets whitespace-split. The old approach
    (`flags.format(...).split()`) corrupted any path containing a space
    (e.g. "C:\\Users\\John Doe\\...") into multiple bogus arguments, which is
    the main reason parsing silently failed/produced nothing.

    Also FIX: stdout/stderr are captured to a log file (not swallowed by
    DEVNULL) and the return code + actual output are checked before a run is
    ever reported as successful.
    """
    tool_path = os.path.join(TOOLS_DIR, tool_exe)
    if not os.path.exists(tool_path):
        detail = f"{tool_exe} not found in tools directory"
        log_warning(f"Skipping {tool_name}: {detail}")
        execution_report["Parsing"][tool_name] = {"status": "skipped", "detail": detail}
        return

    raw_exists = os.path.exists(raw_target)
    raw_has_content = raw_exists and (os.path.isfile(raw_target) or bool(os.listdir(raw_target)))
    if not raw_has_content:
        detail = "No raw data found to parse (source missing or empty)"
        log_warning(f"Skipping {tool_name}: {detail}")
        execution_report["Parsing"][tool_name] = {"status": "skipped", "detail": detail}
        return

    os.makedirs(meta_dir, exist_ok=True)
    cmd = [tool_path] + [tok.format(raw=raw_target, meta=meta_dir) for tok in arg_tokens]

    log_file = os.path.join(meta_dir, f"_{tool_name}_parser_log.txt")
    try:
        print(f"  [*] Parsing {tool_name} ({tool_exe})...")
        with open(log_file, "w", encoding="utf-8", errors="ignore") as lf:
            result = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT, timeout=300)

        produced_output = any(
            os.path.isfile(os.path.join(meta_dir, f)) and os.path.getsize(os.path.join(meta_dir, f)) > 0
            for f in os.listdir(meta_dir)
            if f != os.path.basename(log_file)
        )

        if result.returncode == 0 and produced_output:
            log_success(f"Successfully parsed {tool_name}")
            execution_report["Parsing"][tool_name] = {"status": "success", "log": log_file}
        elif result.returncode == 0 and not produced_output:
            log_warning(f"{tool_name} ran (exit 0) but produced no output — see {log_file}")
            execution_report["Parsing"][tool_name] = {
                "status": "warning", "detail": "No output produced", "log": log_file
            }
        else:
            log_error(f"{tool_name} exited with code {result.returncode} — see {log_file}")
            execution_report["Parsing"][tool_name] = {
                "status": "failed", "detail": f"Exit code {result.returncode}", "log": log_file
            }
    except subprocess.TimeoutExpired:
        log_error(f"Timeout occurred while parsing {tool_name}")
        execution_report["Parsing"][tool_name] = {"status": "failed", "detail": "Timeout"}
    except Exception as e:
        log_error(f"Failed to parse {tool_name}", e)
        execution_report["Parsing"][tool_name] = {"status": "failed", "detail": str(e)}


def run_parsing_automation():
    print("\n[+] Initiating Tool Parsers on Extracted Evidence...")

    run_tool_parser(
        "Prefetch", "PECmd.exe",
        os.path.join(STAGING_ROOT, "Prefetch", "raw"),
        os.path.join(STAGING_ROOT, "Prefetch", "metadata"),
        ["-d", "{raw}", "--csv", "{meta}", "-q"]
    )
    run_tool_parser(
        "Amcache", "AmcacheParser.exe",
        os.path.join(STAGING_ROOT, "Amcache", "raw", "Amcache.hve"),
        os.path.join(STAGING_ROOT, "Amcache", "metadata"),
        ["-f", "{raw}", "--csv", "{meta}", "-q"]
    )
    run_tool_parser(
        "Shimcache", "AppCompatCacheParser.exe",
        os.path.join(STAGING_ROOT, "Registry", "raw", "SYSTEM"),
        os.path.join(STAGING_ROOT, "Registry", "metadata"),
        ["-f", "{raw}", "--csv", "{meta}", "-q"]
    )
    run_tool_parser(
        "Windows Event Logs", "EvtxECmd.exe",
        os.path.join(STAGING_ROOT, "Logs", "raw"),
        os.path.join(STAGING_ROOT, "Logs", "metadata"),
        ["-d", "{raw}", "--csv", "{meta}", "-q"]
    )

    # RegRipper logic is slightly different, requires custom handling
    rip_tool = os.path.join(TOOLS_DIR, "rip.exe")
    registry_raw = os.path.join(STAGING_ROOT, "Registry", "raw")
    reg_meta = os.path.join(STAGING_ROOT, "Registry", "metadata")

    if not os.path.exists(rip_tool):
        log_warning("Skipping RegRipper: rip.exe not found.")
        execution_report["Parsing"]["RegRipper"] = {"status": "skipped", "detail": "rip.exe not found"}
    elif not os.path.exists(registry_raw) or not os.listdir(registry_raw):
        log_warning("Skipping RegRipper: no registry hives collected.")
        execution_report["Parsing"]["RegRipper"] = {"status": "skipped", "detail": "no hives collected"}
    else:
        os.makedirs(reg_meta, exist_ok=True)
        rip_results = {}
        for file in os.listdir(registry_raw):
            if "NTUSER" in file.upper():
                print(f"  [*] Extracting WordWheelQuery from {file} (RegRipper)...")
                out_txt = os.path.join(reg_meta, f"{file}_parsed_history.txt")
                try:
                    with open(out_txt, "w", encoding="utf-8", errors="ignore") as out:
                        result = subprocess.run(
                            [rip_tool, "-r", os.path.join(registry_raw, file), "-p", "wordwheelquery"],
                            stdout=out, stderr=subprocess.STDOUT, timeout=60
                        )
                    ok = result.returncode == 0 and os.path.getsize(out_txt) > 0
                    rip_results[file] = {"status": "success" if ok else "warning",
                                          "detail": "empty output" if not ok else "OK"}
                except subprocess.TimeoutExpired:
                    rip_results[file] = {"status": "failed", "detail": "timeout"}
                    log_error(f"RegRipper timed out on {file}")
                except Exception as e:
                    rip_results[file] = {"status": "failed", "detail": str(e)}
                    log_error(f"Failed running RegRipper on {file}", e)
        if rip_results:
            log_success("Finished running RegRipper plugins.")
        execution_report["Parsing"]["RegRipper"] = rip_results


def print_execution_report():
    print("\n" + "=" * 70)
    print("                     FORENSIC EXECUTION REPORT                      ")
    print("=" * 70)

    print("\n--- RAW COLLECTION (per category) ---")
    if execution_report["Collection"]:
        for category, stats in execution_report["Collection"].items():
            print(f"  [{category}] found={stats['files_found']} "
                  f"copied={stats['files_copied']} failed={stats['files_failed']}")
            for pattern, pstat in stats["patterns"].items():
                if pstat.get("matched_entries", pstat.get("matched", 0)) == 0:
                    print(f"      ! no matches: {pattern}")
                elif pstat.get("files_failed", 0) > 0:
                    print(f"      ! partial failures ({pstat['files_failed']}): {pattern}")
    else:
        print("  (no categories were collected)")

    print("\n--- METADATA PARSING (per tool) ---")
    if execution_report["Parsing"]:
        for tool, result in execution_report["Parsing"].items():
            if isinstance(result, dict) and "status" in result:
                print(f"  [{tool}] status={result['status']}  detail={result.get('detail', '')}")
            else:
                # per-profile / per-file breakdown (autoruns, regripper)
                print(f"  [{tool}]")
                for sub, sub_result in result.items():
                    print(f"      - {sub}: {sub_result.get('status')} {sub_result.get('detail', '')}")
    else:
        print("  (no parsing tools were run)")

    hv = execution_report["HashVerification"]
    print("\n--- HASH VERIFICATION (before/after every copy) ---")
    print(f"  algorithm={hv['algorithm']}  total_files={hv['total_files']}  "
          f"verified={hv['verified']}  mismatched={hv['mismatched']}  hash_errors={hv['hash_errors']}")
    if hv["failures"]:
        print(f"  ! {len(hv['failures'])} file(s) FAILED verification (what went wrong):")
        for fail in hv["failures"]:
            print(f"      - [{fail['category']}] {fail['source_path']}")
            print(f"          -> {fail['error']}")
    else:
        print("  All copied files verified successfully — no corruption detected.")

    gen = execution_report["General"]
    print(f"\n[+] GENERAL SUCCESSES: {len(gen['Successes'])}")
    print(f"[*] GENERAL WARNINGS: {len(gen['Warnings_Skipped'])}")
    for msg in gen["Warnings_Skipped"]:
        print(f"    - {msg}")
    print(f"[-] GENERAL ERRORS: {len(gen['Errors'])}")
    for msg in gen["Errors"]:
        print(f"    - {msg}")

    print("=" * 70)
    print(f"Report complete. Data staged at: {STAGING_ROOT}")


def save_hash_manifest():
    """
    Writes the full per-file audit trail (every file this script attempted to
    copy, whether verified or not) to hash_manifest.csv in the staging root.
    This is the chain-of-custody document: for each file it records source
    path, destination path, algorithm, source hash, destination hash,
    verified status, and the error (if any).
    """
    if not hash_manifest_entries:
        return
    manifest_path = os.path.join(STAGING_ROOT, "hash_manifest.csv")
    try:
        os.makedirs(STAGING_ROOT, exist_ok=True)
        fieldnames = ["timestamp", "category", "source_path", "dest_path", "algorithm",
                      "source_hash", "dest_hash", "size_bytes", "verified", "error"]
        with open(manifest_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(hash_manifest_entries)
        print(f"[+] Hash manifest ({len(hash_manifest_entries)} files) saved to: {manifest_path}")
    except Exception as e:
        print(f"[-] Failed to save hash manifest: {e}")


def save_json_report():
    try:
        os.makedirs(STAGING_ROOT, exist_ok=True)
        report_path = os.path.join(STAGING_ROOT, "execution_report.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(execution_report, f, indent=2, default=str)
        print(f"\n[+] Full JSON report saved to: {report_path}")
    except Exception as e:
        print(f"[-] Failed to save JSON report: {e}")


if __name__ == "__main__":
    print("=====================================================")
    print("      FORENSIC COLLECTION ENGINE v5.0                ")
    print("=====================================================")

    config_path = resolve_config_path()
    ARTIFACT_TARGETS = load_artifact_targets(config_path)

    target_disk = select_drive()
    setup_staging_env(list(ARTIFACT_TARGETS.keys()) + EXTRA_CATEGORIES)

    try:
        if ARTIFACT_TARGETS:
            collect_standard_artifacts(target_disk, ARTIFACT_TARGETS)
        else:
            log_warning("No artifact targets loaded — skipping standard artifact collection entirely.")

        extract_sysinternals_autoruns(target_disk)
        extract_program_data_list(target_disk)
        check_volume_shadow_copies(target_disk)
        scan_for_alternate_data_streams(target_disk)
        run_parsing_automation()
    except KeyboardInterrupt:
        log_error("Execution manually aborted by user (KeyboardInterrupt).")
    except Exception as fatal_e:
        log_error("A FATAL unhandled exception occurred in the main loop", fatal_e)
    finally:
        # Guarantee the report prints and saves, no matter how the script exits
        print_execution_report()
        save_json_report()
        save_hash_manifest()
