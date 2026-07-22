import argparse
import os
import shutil
import hashlib
from pathlib import Path

def calculate_sha256(file_path):
    """Generates a SHA-256 hash for file integrity verification."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in chunks to efficiently handle large memory dumps or files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"

def main():
    # 1. Handle command-line arguments
    parser = argparse.ArgumentParser(description="Automate the ingestion of files into a local 'Extracted_Files' directory.")
    parser.add_argument("file_path", help="The absolute or relative path of the file to process.")
    args = parser.parse_args()

    source_path = Path(args.file_path)

    # 2. Validate the input file
    if not source_path.is_file():
        print(f"[-] Error: The path '{source_path}' is invalid or is not a file.")
        return

    # 3. Determine the script's directory and create 'Extracted_Files'
    # __file__ ensures it builds the folder relative to where the script is located, not where it's executed from
    script_dir = Path(os.path.abspath(__file__)).parent
    extracted_folder = script_dir / "Extracted_Files"
    
    # Create the folder if it doesn't already exist
    extracted_folder.mkdir(parents=True, exist_ok=True)

    # 4. Define the destination path
    destination_path = extracted_folder / source_path.name

    # 5. Execute the file copy
    try:
        # copy2 preserves file metadata (timestamps, permission bits)
        shutil.copy2(source_path, destination_path)
        
        # Calculate the hash of the newly copied file
        file_hash = calculate_sha256(destination_path)

        print("[+] File successfully processed.")
        print(f"    Source:      {source_path.resolve()}")
        print(f"    Destination: {destination_path.resolve()}")
        print(f"    SHA-256:     {file_hash}")
        
    except Exception as e:
        print(f"[-] An error occurred during file transfer: {e}")

if __name__ == "__main__":
    main()