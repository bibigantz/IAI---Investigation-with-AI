IAI FIELD COLLECTION KIT
========================

This is a standalone, offline evidence-collection kit extracted from the
IAI (Investigate with AI) forensic platform. It contains the exact same
collection engine the main platform uses, so anything it collects can be
loaded straight back into IAI as a resumed investigation -- no re-collection,
no format conversion.

WHAT'S IN THIS KIT
  run_kit.exe            Standalone collection engine -- no Python or any
                         other install required on the target machine.
  run_kit.bat            Optional convenience wrapper (warns if not admin).
  tools/                 Eric Zimmerman tools, Sysinternals Autoruns, and
                         RegRipper -- parse the raw artifacts on the spot.
  collector_paths.json   The list of artifact paths/categories to collect.

REQUIREMENTS
  - Windows only (the collector uses Windows-only APIs: VSS, ADS, registry
    hives). Nothing else needs to be installed -- run_kit.exe is fully
    self-contained.
  - Run as Administrator for the fullest capture ($MFT, SAM/SECURITY hives,
    Autoruns). It still runs without admin, just with fewer artifacts.

HOW TO USE
  1. Copy this entire kit folder onto a USB drive or transfer it to the
     target computer -- keep run_kit.exe, tools/, and collector_paths.json
     together in the same folder.
  2. On the target machine, right-click "run_kit.exe" (or "run_kit.bat") and
     choose "Run as administrator" (or just double-click it for a partial
     capture without admin rights).
  3. Choose the drive to investigate when prompted (usually C:), or pass it
     directly from a command prompt:
         run_kit.exe --drive C: --scope ALL
     Scopes: ALL (default), WINDOWS, FILE, MEMORY
  4. Wait for "COLLECTION COMPLETE" and press Enter to close. A new folder
     named
         investigation_staging_<timestamp>_<hostname>
     appears next to run_kit.exe -- that folder IS the evidence package.

LOADING IT BACK INTO IAI
  1. Copy that investigation_staging_... folder onto the IAI analyst
     workstation.
  2. Paste it directly into the IAI project root -- the same folder that
     contains app.py -- NOT into a subfolder.
  3. Open the IAI dashboard's Launch Hub. Click the "Existing Staging
     Sessions" heading to re-scan for investigation folders.
  4. Select it from the list and click "Resume Selected Session". IAI runs
     its full AI agent swarm analysis against the already-collected
     evidence; no drive is re-collected since none is attached locally.

NOTES
  - MEMORY scope does not collect anything itself; drop your memory dump
    (.raw / .dmp / .vmem) into <staging_folder>\MemoryDumps\raw\ before
    loading it into IAI.
  - Every copied file is SHA-256 hashed before and after copy
    (hash_manifest.csv in the staging folder) so evidentiary integrity can
    be verified later.
