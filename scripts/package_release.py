import os
import zipfile

SOURCE_DIR = r"C:\anitgravity fix\fix anything\cipherguard\cipherguard"
DOWNLOADS_DIR = os.path.join(os.environ["USERPROFILE"], "Downloads")
ZIP_NAME = "CipherGuard-Production-Ready.zip"
DEST_ZIP = os.path.join(DOWNLOADS_DIR, ZIP_NAME)

EXCLUDE_DIRS = {"__pycache__", ".pytest_cache", "cipherguard.egg-info", ".git"}
EXCLUDE_EXTS = {".pyc", ".pyo"}
EXCLUDE_FILES = {"cipherguard-audit.jsonl", "cipherguard-plans.db"}

print(f"[*] Packaging CipherGuard into {DEST_ZIP}...")

count = 0
total_uncompressed = 0

with zipfile.ZipFile(DEST_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
    for root, dirs, files in os.walk(SOURCE_DIR):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for f in files:
            if f in EXCLUDE_FILES or any(f.endswith(ext) for ext in EXCLUDE_EXTS):
                continue
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, SOURCE_DIR)
            arcname = os.path.join("cipherguard", rel_path)
            zf.write(full_path, arcname)
            count += 1
            total_uncompressed += os.path.getsize(full_path)

zip_size_mb = os.path.getsize(DEST_ZIP) / (1024 * 1024)
print(f"[SUCCESS] Created {DEST_ZIP}")
print(f"  Files packaged: {count}")
print(f"  Uncompressed: {total_uncompressed / (1024 * 1024):.2f} MB")
print(f"  Zip archive size: {zip_size_mb:.2f} MB")
