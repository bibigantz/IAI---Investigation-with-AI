"""
Assembles the standalone IAI Field Collection Kit: compiles the existing
collection engine (collectors/collector.py, unmodified) into a single
run_kit.exe via PyInstaller, then packages it with the forensic parser
binaries (tools/) and artifact config (collector_paths.json) into a
self-contained folder + zip. The result needs nothing installed on the
target machine -- not Python, not Flask/agents/OpenAI -- just Windows.

Usage:
    python build_field_kit.py

Requires (on the BUILD machine only): pip install pyinstaller

Output:
    dist/IAI_Collection_Kit/       the kit folder, ready to copy to a USB drive
    dist/IAI_Collection_Kit.zip    the same kit, zipped for transfer
"""
import os
import sys
import shutil
import subprocess
import zipfile

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
KIT_NAME = "IAI_Collection_Kit"
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
KIT_DIR = os.path.join(DIST_DIR, KIT_NAME)
BUILD_TMP = os.path.join(DIST_DIR, "_pyinstaller_tmp")


def build_exe():
    entry_script = os.path.join(PROJECT_ROOT, "field_kit", "run_kit.py")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "run_kit",
        "--console",
        "--clean",
        "--noconfirm",
        "--distpath", KIT_DIR,
        "--workpath", BUILD_TMP,
        "--specpath", BUILD_TMP,
        # run_kit.py imports collectors.collector, which lives at
        # PROJECT_ROOT/collectors, not next to the entry script itself.
        "--paths", PROJECT_ROOT,
        entry_script,
    ]
    subprocess.run(cmd, check=True, cwd=PROJECT_ROOT)


def build():
    if os.path.isdir(KIT_DIR):
        shutil.rmtree(KIT_DIR)
    os.makedirs(KIT_DIR)

    # 1. Compile the collection engine into a standalone exe. This is the
    #    exact same collectors/collector.py module the main app already uses
    #    for on-machine collection -- PyInstaller just freezes it plus its
    #    Python runtime so no interpreter is needed on the target machine.
    build_exe()
    shutil.rmtree(BUILD_TMP, ignore_errors=True)

    # 2. Forensic parser binaries.
    shutil.copytree(os.path.join(PROJECT_ROOT, "tools"), os.path.join(KIT_DIR, "tools"))

    # 3. Artifact path config.
    shutil.copy2(os.path.join(PROJECT_ROOT, "collector_paths.json"), KIT_DIR)

    # 4. Convenience wrapper + docs. (run_kit.py source is intentionally not
    #    shipped raw -- run_kit.exe is the supported entry point; the source
    #    lives in field_kit/run_kit.py and collectors/collector.py in this repo
    #    for anyone who wants to audit exactly what the exe was built from.)
    template_dir = os.path.join(PROJECT_ROOT, "field_kit")
    for name in ("run_kit.bat", "README.txt"):
        shutil.copy2(os.path.join(template_dir, name), KIT_DIR)

    zip_path = os.path.join(DIST_DIR, f"{KIT_NAME}.zip")
    if os.path.isfile(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(KIT_DIR):
            for fname in files:
                full_path = os.path.join(root, fname)
                arc_path = os.path.join(KIT_NAME, os.path.relpath(full_path, KIT_DIR))
                zf.write(full_path, arc_path)

    print(f"[+] Kit folder: {KIT_DIR}")
    print(f"[+] Kit zip:    {zip_path}")


if __name__ == "__main__":
    build()
