import hashlib
import csv
import os

# Path to the MalwareBazaar CSV file
CSV_PATH = os.path.join(os.path.dirname(__file__), "malwarebazaar_full.csv")

# Local fallback database
KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR antivirus test file",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty file — possible evasion",
    "cf8bd9dfddff007f75adf4c2be48005c": "Mirai botnet sample",
}

def load_malwarebazaar_csv() -> dict:
    db = {}

    if not os.path.exists(CSV_PATH):
        print(f"WARNING: {CSV_PATH} not found")
        return db

    # Column positions based on MalwareBazaar format
    COL_SHA256    = 1
    COL_SIGNATURE = 8
    COL_FILETYPE  = 6
    COL_FIRSTSEEN = 0
    COL_FILENAME  = 5

    try:
        count = 0
        with open(CSV_PATH, "r",
                  encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if line.startswith("#") or not line:
                    continue

                try:
                    # Split by comma but handle quoted fields
                    values = [
                        v.strip().strip('"')
                        for v in line.split('", "')
                    ]

                    # Clean first and last values
                    if values:
                        values[0]  = values[0].lstrip('"')
                        values[-1] = values[-1].rstrip('"')

                    sha256 = values[COL_SHA256].strip().lower()

                    if sha256 and len(sha256) == 64:
                        db[sha256] = {
                            "malware_family": values[COL_SIGNATURE]
                                if len(values) > COL_SIGNATURE else "Unknown",
                            "file_type":      values[COL_FILETYPE]
                                if len(values) > COL_FILETYPE  else "Unknown",
                            "first_seen":     values[COL_FIRSTSEEN]
                                if len(values) > COL_FIRSTSEEN else "Unknown",
                            "file_name":      values[COL_FILENAME]
                                if len(values) > COL_FILENAME  else "Unknown",
                        }
                        count += 1

                except Exception:
                    continue

        print(f"Loaded {count:,} hashes from MalwareBazaar CSV")

    except Exception as e:
        print(f"Error loading CSV: {e}")

    return db
             
            


# Load once when module starts
# This runs when server starts — not on every scan
MALWAREBAZAAR_DB = load_malwarebazaar_csv()


def check(file_bytes: bytes) -> dict:
    """
    Calculate file hashes and check against:
    1. MalwareBazaar CSV database (offline)
    2. Local fallback database (offline)
    """
    md5    = hashlib.md5(file_bytes).hexdigest()
    sha1   = hashlib.sha1(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    # Step 1 — check MalwareBazaar CSV
    bazaar_match = MALWAREBAZAAR_DB.get(sha256.lower())

    # Step 2 — check local fallback database
    local_match = (
        KNOWN_BAD_HASHES.get(md5) or
        KNOWN_BAD_HASHES.get(sha256)
    )

    # Combine results
    known_malware = None
    source        = None
    details       = None

    if bazaar_match:
        known_malware = bazaar_match["malware_family"]
        source        = "MalwareBazaar CSV"
        details       = bazaar_match
    elif local_match:
        known_malware = local_match
        source        = "Local database"
        details       = {"malware_family": local_match}

    return {
        "md5":           md5,
        "sha1":          sha1,
        "sha256":        sha256,
        "known_malware": known_malware,
        "verdict":       "MALWARE DETECTED" if known_malware
                         else "Not in database",
        "source":        source or "Not found",
        "details":       details,
        "database_size": f"{len(MALWAREBAZAAR_DB):,} hashes loaded",
        "malwarebazaar": "Offline CSV mode — fully private",
    }

