import argparse
import os
import shutil
import hashlib
from pathlib import Path


def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error: {e}"


def main():
    parser = argparse.ArgumentParser(description="Automate the ingestion of files into a local 'Extracted_Files' directory.")
    parser.add_argument("file_path", help="The absolute or relative path of the file to process.")
    args = parser.parse_args()

    source_path = Path(args.file_path)

    if not source_path.is_file():
        print(f"[-] Error: The path '{source_path}' is invalid or is not a file.")
        return

    script_dir = Path(os.path.abspath(__file__)).parent
    extracted_folder = script_dir / "Extracted_Files"
    extracted_folder.mkdir(parents=True, exist_ok=True)

    destination_path = extracted_folder / source_path.name

    try:
        shutil.copy2(source_path, destination_path)
        file_hash = calculate_sha256(destination_path)
        print("[+] File successfully processed.")
        print(f"    Source:      {source_path.resolve()}")
        print(f"    Destination: {destination_path.resolve()}")
        print(f"    SHA-256:     {file_hash}")
    except Exception as e:
        print(f"[-] An error occurred during file transfer: {e}")


if __name__ == "__main__":
    main()
