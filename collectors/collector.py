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
import argparse
from datetime import datetime

try:
    sys.stdout.reconfigure(errors='replace')
    sys.stderr.reconfigure(errors='replace')
except Exception:
    pass

if getattr(sys, "frozen", False):
    # Running as a PyInstaller-built .exe (the field collection kit): __file__
    # resolves inside the frozen bundle, not next to the real tools/ folder,
    # so anchor everything to the actual executable's directory instead.
    COLLECTOR_DIR = os.path.dirname(os.path.abspath(sys.executable))
    PROJECT_ROOT = COLLECTOR_DIR
else:
    COLLECTOR_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(COLLECTOR_DIR)
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")
STAGING_ROOT = os.path.join(PROJECT_ROOT, f"investigation_staging_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

EXTRA_CATEGORIES = ["ProgramDataList", "AlternateDataStreams", "VSS_Shadows", "SysinternalsAutoruns",
    "CommonMalwarePaths", "MFT", "Timeline"]
APPDATA_PUBLIC_MAX_FILE_BYTES = 25 * 1024 * 1024  # 25MB cap on a single top-level dropped file

FILE_CATEGORIES = ["Downloads", "TempFolder", "Shortcuts", "ProgramDataList",
    "AlternateDataStreams", "BrowserHistory", "StartupFolders", "ScheduledTasks",
    "JumpLists", "Thumbcache", "RecycleBin", "WindowsErrorReporting",
    "HostsFile", "SetupAPILogs", "RDPCache", "PowerShellHistory"]
HASH_ALGORITHM = "sha256"
PROGRESS_FILENAME = "collection_progress.json"
STOP_FLAG_FILENAME = "STOP_REQUESTED.flag"
execution_report = {
    "Collection": {},
    "Parsing": {},
    "HashVerification": {
        "algorithm": HASH_ALGORITHM,
        "total_files": 0,
        "verified": 0,
        "mismatched": 0,
        "hash_errors": 0,
        "failures": []
    },
    "General": {
        "Successes": [],
        "Warnings_Skipped": [],
        "Errors": []
    }
}
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

def _progress_path(staging_root):
    return os.path.join(staging_root, PROGRESS_FILENAME)

def _stop_flag_path(staging_root):
    return os.path.join(staging_root, STOP_FLAG_FILENAME)

def load_progress(staging_root, drive_letter, scope):
    """Loads collection_progress.json if this staging dir already has one
    (a resume), otherwise returns a fresh progress dict. Recording
    drive_letter/scope here -- not just which categories are done -- is
    what lets Continue Collecting re-invoke this exact same collection run
    without the analyst having to re-enter anything."""
    path = _progress_path(staging_root)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                progress = json.load(f)
            progress.setdefault("completed_categories", [])
            progress.setdefault("completed_steps", [])
            log_success(
                f"Resuming previous collection -- {len(progress['completed_categories'])} categor"
                f"{'y' if len(progress['completed_categories']) == 1 else 'ies'} already collected."
            )
            return progress
        except Exception as e:
            log_warning(f"Could not read existing {PROGRESS_FILENAME} ({e}) -- starting collection progress fresh.")
    return {
        "drive_letter": drive_letter,
        "scope": scope,
        "completed_categories": [],
        "completed_steps": [],
        "stopped": False,
        "started_at": datetime.now().isoformat(),
    }

def save_progress(staging_root, progress):
    progress["last_updated"] = datetime.now().isoformat()
    try:
        os.makedirs(staging_root, exist_ok=True)
        with open(_progress_path(staging_root), "w", encoding="utf-8") as f:
            json.dump(progress, f, indent=2)
    except Exception as e:
        log_error("Failed to save collection_progress.json", e)

def is_stop_requested(staging_root):
    return os.path.isfile(_stop_flag_path(staging_root))

def clear_stop_flag(staging_root):
    """Called at the start of every run (fresh or resumed) so a stop flag
    left over from a *previous* stop request doesn't immediately re-trigger
    -- the web app clears it too before resuming, this is just a safety net
    for direct CLI use."""
    try:
        os.remove(_stop_flag_path(staging_root))
    except FileNotFoundError:
        pass
    except Exception as e:
        log_warning(f"Could not clear stale stop flag: {e}")

def _run_step_once(progress, step_name, func, *args, **kwargs):
    """Runs one named atomic collection step (autoruns, MFT, VSS query, ...)
    unless it's already marked done in progress['completed_steps'] (a
    resume skips it and everything it already produced stays untouched on
    disk), then marks it done and saves progress. Checks the stop flag
    *before* starting the step -- these steps aren't internally
    interruptible, so stop granularity here is "between named steps," same
    as collect_standard_artifacts' "between categories." Returns False
    (without running) if a stop was already requested."""
    if is_stop_requested(STAGING_ROOT):
        return False
    if step_name in progress["completed_steps"]:
        print(f"[*] Skipping already-completed step: {step_name}")
        return True
    func(*args, **kwargs)
    progress["completed_steps"].append(step_name)
    save_progress(STAGING_ROOT, progress)
    return True

def resolve_config_path(config_arg=None):
    if config_arg and os.path.exists(config_arg):
        return config_arg
    candidates = [
        os.path.join(PROJECT_ROOT, "collector_paths.json"),
        os.path.join(os.getcwd(), "collector_paths.json"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]

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
    parts = path_str.split(os.sep)
    if "Users" in parts:
        try:
            idx = parts.index("Users")
            return f"{parts[idx + 1]}_"
        except IndexError:
            pass
    return ""

def compute_file_hash(path, algorithm=HASH_ALGORITHM, chunk_size=4 * 1024 * 1024):
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def copy_file_verified(src, dest_file, algorithm=HASH_ALGORITHM):
    result = {"success": False, "verified": False, "src_hash": None, "dest_hash": None, "size_bytes": None, "error": None}
    try:
        result["src_hash"] = compute_file_hash(src, algorithm)
    except Exception as e:
        result["error"] = f"Failed to hash source before copy: {e}"
        return result
    try:
        shutil.copy2(src, dest_file)
        result["success"] = True
    except PermissionError as e:
        result["error"] = f"Permission denied during copy (file likely locked/in-use): {e}"
        return result
    except Exception as e:
        result["error"] = f"Copy failed: {e}"
        return result
    try:
        result["dest_hash"] = compute_file_hash(dest_file, algorithm)
        result["size_bytes"] = os.path.getsize(dest_file)
    except Exception as e:
        result["error"] = f"Failed to hash destination after copy: {e}"
        return result
    if result["src_hash"] == result["dest_hash"]:
        result["verified"] = True
    else:
        result["error"] = "Hash mismatch after copy -- destination file is corrupt/incomplete"
        try:
            os.remove(dest_file)
            result["error"] += " (corrupted copy removed)"
        except Exception as cleanup_e:
            result["error"] += f" (could NOT remove corrupted copy: {cleanup_e})"
    return result

def record_manifest_entry(category, src, dest_file, verify_result):
    entry = {
        "timestamp": datetime.now().isoformat(), "category": category,
        "source_path": src, "dest_path": dest_file, "algorithm": HASH_ALGORITHM,
        "source_hash": verify_result["src_hash"], "dest_hash": verify_result["dest_hash"],
        "size_bytes": verify_result["size_bytes"], "verified": verify_result["verified"],
        "error": verify_result["error"],
    }
    hash_manifest_entries.append(entry)
    hv = execution_report["HashVerification"]
    hv["total_files"] += 1
    if verify_result["verified"]:
        hv["verified"] += 1
        log_success(f"Collected & hash-verified -> {os.path.basename(dest_file)} ({HASH_ALGORITHM}={verify_result['dest_hash'][:12]}...)")
    else:
        if verify_result["src_hash"] is not None and verify_result["dest_hash"] is not None:
            hv["mismatched"] += 1
        else:
            hv["hash_errors"] += 1
        hv["failures"].append(entry)
        log_error(f"Hash verification FAILED for {src} -> {dest_file} | {verify_result['error']}")

def copy_preserving_context(src, dest_dir, category="Unknown"):
    if not os.path.isfile(src):
        return False
    filename = _username_prefix(src) + os.path.basename(src)
    dest_file = os.path.join(dest_dir, filename)
    result = copy_file_verified(src, dest_file)
    record_manifest_entry(category, src, dest_file, result)
    return result["verified"]

def copy_matched_path(src, dest_dir, category="Unknown"):
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
    return (0, 0)

def collect_standard_artifacts(target_drive, artifact_targets, progress=None):
    """If `progress` is given, categories already in
    progress['completed_categories'] are skipped entirely (a resumed run),
    and progress is saved to disk after each category completes so a stop
    request between categories loses at most the one category in flight,
    not everything collected so far. Returns True if it ran to completion,
    False if it stopped early because a stop was requested."""
    print(f"\n[+] Starting Standard File Collection from {target_drive}...")
    completed = set(progress["completed_categories"]) if progress else set()
    for category, paths in artifact_targets.items():
        if category in completed:
            print(f"[*] Skipping already-collected category: {category}")
            continue
        if progress and is_stop_requested(STAGING_ROOT):
            log_warning(f"Stop requested -- halting before category '{category}'. Progress saved.")
            return False
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
                "matched_entries": len(matched), "files_copied": copied, "files_failed": failed
            }
        execution_report["Collection"][category] = cat_stats
        if progress is not None:
            progress["completed_categories"].append(category)
            save_progress(STAGING_ROOT, progress)
    return True

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
    profiles = [None]
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
                        dest_file = os.path.join(bin_dest, f"{prof_name}_{os.path.basename(actual_path)}")
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

def extract_high_risk_appdata_and_public(target_drive):
    """
    Shallow (non-recursive) sweep of each user's AppData\\Local, AppData\\Roaming,
    and the shared Public folder -- the classic top-level dropper locations
    (e.g. %APPDATA%\\update.exe, %LOCALAPPDATA%\\svchost.exe posing as a system
    binary). Only top-level FILES are hash-verified and copied; subdirectories
    are recorded in a manifest but never recursed into, since a full recursive
    copy of AppData\\Local would drag in entire browser profiles/caches --
    unbounded in size and mostly forensic noise for this specific check.
    """
    print("\n[*] Sweeping top-level AppData & Public directories for dropped payloads...")
    category = "CommonMalwarePaths"
    raw_dest = os.path.join(STAGING_ROOT, category, "raw")
    meta_dest = os.path.join(STAGING_ROOT, category, "metadata")
    os.makedirs(raw_dest, exist_ok=True)
    os.makedirs(meta_dest, exist_ok=True)

    manifest = []
    cat_stats = {"files_found": 0, "files_copied": 0, "files_failed": 0, "dirs_noted": 0}

    sweep_targets = [("Public", os.path.join(target_drive, "Users", "Public"))]
    try:
        for user_dir in glob.glob(os.path.join(target_drive, "Users", "*")):
            if not os.path.isdir(user_dir) or os.path.basename(user_dir).lower() == "public":
                continue
            sweep_targets.append(("AppData_Local", os.path.join(user_dir, "AppData", "Local")))
            sweep_targets.append(("AppData_Roaming", os.path.join(user_dir, "AppData", "Roaming")))
    except Exception as e:
        log_error("Failed to enumerate user profiles for AppData/Public sweep", e)

    for label, directory in sweep_targets:
        if not os.path.isdir(directory):
            continue
        try:
            entries = list(os.scandir(directory))
        except Exception as e:
            log_warning(f"Could not enumerate {directory}: {e}")
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    manifest.append({"location": label, "type": "dir", "name": entry.name, "path": entry.path})
                    cat_stats["dirs_noted"] += 1
                    continue
                if not entry.is_file():
                    continue
                cat_stats["files_found"] += 1
                size = entry.stat().st_size
                manifest_entry = {
                    "location": label, "type": "file", "name": entry.name,
                    "path": entry.path, "size_bytes": size,
                }
                if size > APPDATA_PUBLIC_MAX_FILE_BYTES:
                    manifest_entry["copied"] = False
                    manifest_entry["skip_reason"] = f"exceeds {APPDATA_PUBLIC_MAX_FILE_BYTES}-byte top-level cap"
                    cat_stats["files_failed"] += 1
                else:
                    prefix = _username_prefix(entry.path)
                    dest_file = os.path.join(raw_dest, f"{label}_{prefix}{entry.name}")
                    result = copy_file_verified(entry.path, dest_file)
                    record_manifest_entry(category, entry.path, dest_file, result)
                    manifest_entry["copied"] = result["verified"]
                    if result["verified"]:
                        cat_stats["files_copied"] += 1
                    else:
                        cat_stats["files_failed"] += 1
                        manifest_entry["skip_reason"] = result["error"]
                manifest.append(manifest_entry)
            except Exception as e:
                log_error(f"Failed processing entry {getattr(entry, 'path', '?')}", e)

    try:
        with open(os.path.join(meta_dest, "appdata_public_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
        log_success(
            f"AppData/Public sweep complete: {cat_stats['files_copied']} top-level file(s) staged, "
            f"{cat_stats['dirs_noted']} subdirectory entries noted (not recursed)."
        )
    except Exception as e:
        log_error("Failed to save AppData/Public manifest", e)

    execution_report["Collection"][category] = cat_stats

def extract_mft(target_drive):
    """
    Copy the volume's $MFT (NTFS's own file-record table) so MFTECmd can
    later diff $STANDARD_INFORMATION vs $FILE_NAME timestamps per file --
    the classic timestomping tell. $MFT is an NTFS pseudo-file exposed at
    the volume root; reading it requires FILE_FLAG_BACKUP_SEMANTICS access,
    which in turn requires SeBackupPrivilege (i.e. an administrator). This
    is expected to fail gracefully on a standard user account -- exactly
    like every other privileged artifact in this collector, it's logged as
    a warning and the run continues.
    """
    print("\n[*] Attempting to collect the Master File Table ($MFT)...")
    category = "MFT"
    raw_dest = os.path.join(STAGING_ROOT, category, "raw")
    os.makedirs(raw_dest, exist_ok=True)
    mft_src = os.path.join(target_drive, "$MFT")
    dest_file = os.path.join(raw_dest, "$MFT")

    if not os.path.exists(mft_src):
        log_warning(f"$MFT not accessible at {mft_src} (requires SeBackupPrivilege / administrator).")
        execution_report["Collection"][category] = {"files_found": 0, "files_copied": 0, "files_failed": 1}
        return

    result = copy_file_verified(mft_src, dest_file)
    record_manifest_entry(category, mft_src, dest_file, result)
    execution_report["Collection"][category] = {
        "files_found": 1,
        "files_copied": 1 if result["verified"] else 0,
        "files_failed": 0 if result["verified"] else 1,
    }
    if result["verified"]:
        log_success("Collected and hash-verified $MFT.")
    else:
        log_error(f"Failed to collect $MFT: {result['error']}")

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
            for f in os.listdir(meta_dir) if f != os.path.basename(log_file)
        )
        if result.returncode == 0 and produced_output:
            log_success(f"Successfully parsed {tool_name}")
            execution_report["Parsing"][tool_name] = {"status": "success", "log": log_file}
        elif result.returncode == 0 and not produced_output:
            log_warning(f"{tool_name} ran (exit 0) but produced no output -- see {log_file}")
            execution_report["Parsing"][tool_name] = {"status": "warning", "detail": "No output produced", "log": log_file}
        else:
            log_error(f"{tool_name} exited with code {result.returncode} -- see {log_file}")
            execution_report["Parsing"][tool_name] = {"status": "failed", "detail": f"Exit code {result.returncode}", "log": log_file}
    except subprocess.TimeoutExpired:
        log_error(f"Timeout occurred while parsing {tool_name}")
        execution_report["Parsing"][tool_name] = {"status": "failed", "detail": "Timeout"}
    except Exception as e:
        log_error(f"Failed to parse {tool_name}", e)
        execution_report["Parsing"][tool_name] = {"status": "failed", "detail": str(e)}

def run_parsing_automation(scope="ALL"):
    print("\n[+] Initiating Tool Parsers on Extracted Evidence...")
    is_file_scope = scope.upper() == "FILE"
    is_memory_scope = scope.upper() == "MEMORY"

    if is_memory_scope:
        log_success("Memory Analysis scope: skipping parsing automation.")
        return

    run_tool_parser("Prefetch", "PECmd.exe",
        os.path.join(STAGING_ROOT, "Prefetch", "raw"),
        os.path.join(STAGING_ROOT, "Prefetch", "metadata"),
        ["-d", "{raw}", "--csv", "{meta}", "-q"])
    if not is_file_scope:
        run_tool_parser("Amcache", "AmcacheParser.exe",
            os.path.join(STAGING_ROOT, "Amcache", "raw", "Amcache.hve"),
            os.path.join(STAGING_ROOT, "Amcache", "metadata"),
            ["-f", "{raw}", "--csv", "{meta}", "-q"])
        run_tool_parser("Shimcache", "AppCompatCacheParser.exe",
            os.path.join(STAGING_ROOT, "Registry", "raw", "SYSTEM"),
            os.path.join(STAGING_ROOT, "Registry", "metadata"),
            ["-f", "{raw}", "--csv", "{meta}", "-q"])
        run_tool_parser("MFT", "MFTECmd.exe",
            os.path.join(STAGING_ROOT, "MFT", "raw", "$MFT"),
            os.path.join(STAGING_ROOT, "MFT", "metadata"),
            ["-f", "{raw}", "--csv", "{meta}", "--csvf", "mft_output.csv"])
        run_tool_parser("Windows Event Logs", "EvtxECmd.exe",
            os.path.join(STAGING_ROOT, "Logs", "raw"),
            os.path.join(STAGING_ROOT, "Logs", "metadata"),
            ["-d", "{raw}", "--csv", "{meta}", "-q"])
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
                                stdout=out, stderr=subprocess.STDOUT, timeout=60)
                        ok = result.returncode == 0 and os.path.getsize(out_txt) > 0
                        rip_results[file] = {"status": "success" if ok else "warning", "detail": "empty output" if not ok else "OK"}
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
            print(f"  [{category}] found={stats['files_found']} copied={stats['files_copied']} failed={stats['files_failed']}")
            for pattern, pstat in stats.get("patterns", {}).items():
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
                print(f"  [{tool}]")
                for sub, sub_result in result.items():
                    print(f"      - {sub}: {sub_result.get('status')} {sub_result.get('detail', '')}")
    else:
        print("  (no parsing tools were run)")
    hv = execution_report["HashVerification"]
    print("\n--- HASH VERIFICATION (before/after every copy) ---")
    print(f"  algorithm={hv['algorithm']}  total_files={hv['total_files']}  verified={hv['verified']}  mismatched={hv['mismatched']}  hash_errors={hv['hash_errors']}")
    if hv["failures"]:
        print(f"  ! {len(hv['failures'])} file(s) FAILED verification:")
        for fail in hv["failures"]:
            print(f"      - [{fail['category']}] {fail['source_path']} -> {fail['error']}")
    else:
        print("  All copied files verified successfully.")
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

def _load_prior_state_for_resume(staging_root):
    """A resumed run must not silently lose the hash-verification record and
    collection stats for categories collected *before* the stop -- both
    execution_report.json and hash_manifest.csv are overwritten (not
    appended) on every save, so without this, resuming would collect the
    remaining categories fine but the final report/manifest would only ever
    show this run's partial slice, even though every previously-collected
    file is still safely on disk."""
    report_path = os.path.join(staging_root, "execution_report.json")
    if os.path.isfile(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                prior = json.load(f)
            execution_report["Collection"] = prior.get("Collection", {})
            execution_report["Parsing"] = prior.get("Parsing", {})
            prior_hv = prior.get("HashVerification", {})
            execution_report["HashVerification"]["total_files"] = prior_hv.get("total_files", 0)
            execution_report["HashVerification"]["verified"] = prior_hv.get("verified", 0)
            execution_report["HashVerification"]["mismatched"] = prior_hv.get("mismatched", 0)
            execution_report["HashVerification"]["hash_errors"] = prior_hv.get("hash_errors", 0)
            execution_report["HashVerification"]["failures"] = prior_hv.get("failures", [])
            execution_report["General"] = prior.get(
                "General", {"Successes": [], "Warnings_Skipped": [], "Errors": []}
            )
        except Exception as e:
            log_warning(f"Could not load prior execution_report.json for resume ({e}) -- stats restart from this run only.")

    manifest_path = os.path.join(staging_root, "hash_manifest.csv")
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path, "r", newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    row["size_bytes"] = int(row["size_bytes"]) if row.get("size_bytes") else None
                    row["verified"] = row.get("verified") in ("True", "true", "1")
                    hash_manifest_entries.append(row)
        except Exception as e:
            log_warning(f"Could not load prior hash_manifest.csv for resume ({e}).")


def run_folder_collection(folder_path: str, staging_root: str) -> dict:
    """
    Ingest a single arbitrary folder for File / Malware analysis, instead of
    sweeping an entire drive. `folder_path` can be nested arbitrarily deep
    on any drive (e.g. "D:\\Cases\\test\\suspect_files") -- unlike
    run_collection(), it is not assumed to be a drive root, so none of the
    Windows-specific artifact categories (registry hives, $MFT, VSS, etc.)
    apply here; every file underneath it is simply hashed, copied, and
    queued into ProgramDataList for the File Analysis pipeline to pick up.

    Args:
        folder_path: Absolute path to the folder to ingest.
        staging_root: Absolute path to the staging directory.

    Returns:
        The execution_report dict with collection results.
    """
    global STAGING_ROOT
    STAGING_ROOT = staging_root
    os.makedirs(STAGING_ROOT, exist_ok=True)

    execution_report["Collection"] = {}
    execution_report["Parsing"] = {}
    execution_report["HashVerification"] = {
        "algorithm": HASH_ALGORITHM, "total_files": 0, "verified": 0,
        "mismatched": 0, "hash_errors": 0, "failures": []
    }
    execution_report["General"] = {"Successes": [], "Warnings_Skipped": [], "Errors": []}
    hash_manifest_entries.clear()

    category = "ProgramDataList"
    setup_staging_env([category])

    if not os.path.isdir(folder_path):
        log_error(f"Target folder not found or inaccessible: {folder_path}")
        execution_report["Collection"][category] = {"files_found": 0, "files_copied": 0, "files_failed": 0}
    else:
        print(f"\n[+] Ingesting folder: {folder_path}...")
        raw_dest = os.path.join(STAGING_ROOT, category, "raw")
        copied, failed = copy_matched_path(folder_path, raw_dest, category)
        execution_report["Collection"][category] = {
            "files_found": copied + failed, "files_copied": copied, "files_failed": failed
        }
        log_success(f"Folder ingestion complete: {copied} file(s) verified, {failed} failed.")

    print_execution_report()
    save_json_report()
    save_hash_manifest()

    execution_report["stopped_by_user"] = False
    return dict(execution_report)


def run_collection(target_drive: str, staging_root: str, config_path: str = None, scope: str = "ALL") -> dict:
    """
    Run the full evidence collection pipeline programmatically.

    Args:
        target_drive: Drive letter with trailing backslash, e.g. "D:\\"
        staging_root: Absolute path to the staging directory
        config_path: Optional path to collector_paths.json
        scope: Collection scope - "ALL", "WINDOWS", "FILE", or "MEMORY"

    Returns:
        The execution_report dict with collection results
    """
    if not target_drive.endswith("\\"):
        target_drive += "\\"

    global STAGING_ROOT
    STAGING_ROOT = staging_root
    os.makedirs(STAGING_ROOT, exist_ok=True)

    # A resumed run (collection_progress.json already exists here from a
    # previous stop) must not wipe the hash-verification record and stats
    # for whatever was already collected -- see _load_prior_state_for_resume.
    # A genuinely fresh run starts every counter blank, as before.
    is_resume = os.path.isfile(_progress_path(STAGING_ROOT))
    execution_report["Collection"] = {}
    execution_report["Parsing"] = {}
    execution_report["HashVerification"] = {
        "algorithm": HASH_ALGORITHM, "total_files": 0, "verified": 0,
        "mismatched": 0, "hash_errors": 0, "failures": []
    }
    execution_report["General"] = {"Successes": [], "Warnings_Skipped": [], "Errors": []}
    hash_manifest_entries.clear()
    if is_resume:
        _load_prior_state_for_resume(STAGING_ROOT)  # re-seeds the dicts/list just cleared above

    progress = load_progress(STAGING_ROOT, target_drive, scope)
    # A stop flag only makes sense for *this specific run in progress* -- if
    # one is somehow already sitting here when we start (a stale leftover),
    # clear it so this fresh invocation doesn't halt before doing anything.
    clear_stop_flag(STAGING_ROOT)

    is_file_scope = scope.upper() in ("FILE",)
    is_memory_scope = scope.upper() in ("MEMORY",)
    is_memory_or_file = is_file_scope or is_memory_scope

    resolved_config = resolve_config_path(config_path)
    all_artifact_targets = load_artifact_targets(resolved_config)

    # Filter artifact categories by scope
    if is_file_scope:
        artifact_targets = {k: v for k, v in all_artifact_targets.items() if k in FILE_CATEGORIES}
    else:
        artifact_targets = all_artifact_targets

    if is_memory_scope:
        all_categories = ["MemoryDumps"]
    else:
        all_categories = list(artifact_targets.keys())
        if not is_file_scope:
            all_categories += EXTRA_CATEGORIES
    setup_staging_env(all_categories)

    # Each step below only runs if nothing has requested a stop yet, and
    # each one that actually runs checks for a stop request immediately
    # before starting -- see _run_step_once()/collect_standard_artifacts()'s
    # own docstrings for exactly what granularity that gives. `stopped`
    # short-circuits every remaining step the moment any one of them halts.
    stopped = False
    try:
        if is_memory_scope:
            log_success("Memory Analysis scope: skipping evidence collection. Upload memory dumps to MemoryDumps/raw.")
        else:
            if artifact_targets:
                if not collect_standard_artifacts(target_drive, artifact_targets, progress=progress):
                    stopped = True
            else:
                log_warning("No artifact targets loaded -- skipping standard artifact collection entirely.")

            if not stopped and not is_memory_or_file:
                stopped = not _run_step_once(progress, "autoruns", extract_sysinternals_autoruns, target_drive)

            if not stopped:
                stopped = not _run_step_once(progress, "program_data_list", extract_program_data_list, target_drive)
            if not stopped:
                stopped = not _run_step_once(
                    progress, "appdata_public_sweep", extract_high_risk_appdata_and_public, target_drive
                )

            if not stopped and not is_memory_or_file:
                stopped = not _run_step_once(progress, "vss_shadows", check_volume_shadow_copies, target_drive)
                if not stopped:
                    stopped = not _run_step_once(progress, "mft", extract_mft, target_drive)

            if not stopped:
                stopped = not _run_step_once(progress, "ads_scan", scan_for_alternate_data_streams, target_drive)

            if not stopped:
                stopped = not _run_step_once(progress, "parsing_automation", run_parsing_automation, scope=scope)

        progress["stopped"] = stopped
        save_progress(STAGING_ROOT, progress)
        if stopped:
            log_warning(
                "Collection halted by analyst stop request -- progress saved. "
                "Re-run with the same --staging directory (or click Continue Collecting) to pick up where this left off."
            )
    except KeyboardInterrupt:
        log_error("Execution manually aborted by user (KeyboardInterrupt).")
    except Exception as fatal_e:
        log_error("A FATAL unhandled exception occurred in the main loop", fatal_e)
    finally:
        print_execution_report()
        save_json_report()
        save_hash_manifest()

    execution_report["stopped_by_user"] = stopped
    return dict(execution_report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IAI Forensic Collection Engine")
    parser.add_argument("--drive", help="Target drive letter (e.g. D:). Omit for interactive selection.")
    parser.add_argument("--folder", help="Ingest a single arbitrary folder (any depth, any drive) instead of a whole drive. Takes precedence over --drive.")
    parser.add_argument("--staging", help="Staging directory path. Auto-generated if omitted.")
    parser.add_argument("--config", help="Path to collector_paths.json config file.")
    parser.add_argument("--scope", choices=["ALL", "WINDOWS", "FILE", "MEMORY"], default="ALL",
                        help="Collection scope filter (default: ALL)")
    args = parser.parse_args()

    print("=====================================================")
    print("      FORENSIC COLLECTION ENGINE v5.0                ")
    print("=====================================================")

    if args.staging:
        STAGING_ROOT = args.staging

    if args.folder:
        run_folder_collection(folder_path=args.folder, staging_root=STAGING_ROOT)
    else:
        target_disk = args.drive if args.drive else select_drive()
        run_collection(
            target_drive=target_disk,
            staging_root=STAGING_ROOT,
            config_path=args.config,
            scope=args.scope,
        )
