"""
IAI Field Collection Kit -- standalone entry point.

Runs the exact same collection engine the main IAI platform uses
(collectors/collector.py), with no Flask/agents/OpenAI dependency, so it can
be copied onto a target machine and run there on its own. The staging folder
it produces is byte-for-byte the same layout IAI already expects, so it can
be copied back and loaded as a resumed investigation with zero conversion.
"""
import os
import sys
import socket
import argparse
from datetime import datetime

if getattr(sys, "frozen", False):
    # Running as the PyInstaller-built run_kit.exe: collectors.collector is
    # bundled inside the exe itself, and tools/ + collector_paths.json live
    # next to the exe on disk.
    KIT_ROOT = os.path.dirname(os.path.abspath(sys.executable))
else:
    KIT_ROOT = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, KIT_ROOT)

from collectors.collector import run_collection, select_drive  # noqa: E402


def _is_admin():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _sanitize_label(label):
    return "".join(c for c in label if c.isalnum() or c in ("-", "_")) or "kit"


def main():
    parser = argparse.ArgumentParser(description="IAI Field Collection Kit")
    parser.add_argument("--drive", help="Target drive letter, e.g. C: or D: (omit to choose interactively)")
    parser.add_argument("--scope", choices=["ALL", "WINDOWS", "FILE", "MEMORY"], default="ALL",
                         help="Collection scope filter (default: ALL)")
    parser.add_argument("--label", help="Label appended to the output folder name (default: this machine's hostname)")
    args = parser.parse_args()

    print("=" * 70)
    print("  IAI FIELD COLLECTION KIT")
    print("  Standalone offline evidence acquisition -- no installation required.")
    print("=" * 70)

    if os.name == "nt" and not _is_admin():
        print("\n[!] WARNING: not running as Administrator.")
        print("    $MFT, SAM/SECURITY hives, and Autoruns extraction will be skipped.")
        print("    Right-click run_kit.bat -> 'Run as administrator' for a full capture.\n")

    target_drive = args.drive if args.drive else select_drive()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    label = _sanitize_label(args.label) if args.label else _sanitize_label(socket.gethostname())
    staging_dir = os.path.join(KIT_ROOT, f"investigation_staging_{timestamp}_{label}")

    print(f"\n[+] Target drive : {target_drive}")
    print(f"[+] Scope        : {args.scope}")
    print(f"[+] Staging to   : {staging_dir}\n")

    run_collection(target_drive=target_drive, staging_root=staging_dir, scope=args.scope)

    print("\n" + "=" * 70)
    print("  COLLECTION COMPLETE")
    print("=" * 70)
    print(f"  Evidence staged at:\n    {staging_dir}")
    print("\n  NEXT STEPS")
    print("  1. Copy that folder onto removable media / a secure transfer channel.")
    print("  2. On the IAI analyst workstation, paste it directly into the IAI")
    print("     project root -- the same folder that contains app.py.")
    print("  3. In the Launch Hub, click the 'Existing Staging Sessions' heading")
    print("     to re-scan, select it, then click 'Resume Selected Session'.")
    print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Aborted by user.")
    except Exception as e:
        print(f"\n[-] FATAL: {e}")
    finally:
        # Keep the console window open when double-clicked directly instead
        # of via run_kit.bat, so the report doesn't vanish on exit.
        input("\nPress Enter to close this window...")
