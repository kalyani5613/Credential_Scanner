# download_yara_rules.py — fixed URLs

import os
import urllib.request
import zipfile
import io

RULES_DIR = os.path.join("attachment_scanner", "yara_rules")

SOURCES = [
    {
        "name":          "Yara-Rules community collection",
        "url":           "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip",
        "dest_subfolder":"yara_rules_community",
    },
    {
        "name":          "Neo23x0 signature-base",
        "url":           "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        "dest_subfolder":"signature_base",
    },
    {
        "name":          "ElasticSecurity YARA rules",
        "url":           "https://github.com/elastic/protections-artifacts/archive/refs/heads/main.zip",
        "dest_subfolder":"elastic_rules",
    },
]


def download_zip_rules(source: dict):
    print(f"\nDownloading {source['name']}...")
    dest = os.path.join(RULES_DIR, source["dest_subfolder"])
    os.makedirs(dest, exist_ok=True)

    try:
        req = urllib.request.Request(
            source["url"],
            headers={"User-Agent": "Mozilla/5.0"}
        )
        print("  Fetching ZIP (this may take a moment)...")
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()

        print(f"  Downloaded {len(data) // (1024*1024)} MB — extracting...")

        with zipfile.ZipFile(io.BytesIO(data)) as z:
            yar_files = [
                n for n in z.namelist()
                if n.endswith(".yar") or n.endswith(".yara")
            ]
            count = 0
            for yar in yar_files:
                filename = os.path.basename(yar)
                if not filename:
                    continue
                dest_file = os.path.join(dest, filename)
                with z.open(yar) as src, open(dest_file, "wb") as dst:
                    dst.write(src.read())
                count += 1

        print(f"  ✓ Extracted {count} YARA rule files")
        return count

    except Exception as e:
        print(f"  ✗ Failed: {e}")
        return 0


def main():
    print("=" * 55)
    print("  YARA Rules Downloader")
    print("=" * 55)

    os.makedirs(RULES_DIR, exist_ok=True)

    total = 0
    for source in SOURCES:
        count = download_zip_rules(source)
        total += count

    # Count existing rules too
    existing = sum(
        1 for root, _, files in os.walk(RULES_DIR)
        for f in files if f.endswith((".yar", ".yara"))
    )

    print(f"\n{'=' * 55}")
    print(f"  Total rule files on disk: {existing}")
    print(f"  Location: {os.path.abspath(RULES_DIR)}")
    print(f"{'=' * 55}")


if __name__ == "__main__":
    main()