import hashlib
import csv
import json
from pathlib import Path
from datetime import datetime
import platform


# PROJECT FOLDERS
project_folder = Path(__file__).parent
evidence_folder = project_folder / "evidence"
reports_folder = project_folder / "reports"

# Create reports folder if it does not exist
reports_folder.mkdir(exist_ok=True)


# CALCULATE SHA-256 HASH
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(1024 * 1024)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# DETECT FILE TYPE USING FILE SIGNATURES
def detect_file_type(file_path):
    with open(file_path, "rb") as file:
        header = file.read(16)

    if header.startswith(b"\xff\xd8\xff"):
        return "JPEG Image"

    elif header.startswith(b"%PDF-"):
        return "PDF Document"

    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG Image"

    elif b"\x00" not in header:
        return "Text or unknown format (heuristic)"

    else:
        return "Unknown Binary Format"


# EXPECTED FILE TYPES
expected_types = {
    ".jpg": "JPEG Image",
    ".jpeg": "JPEG Image",
    ".pdf": "PDF Document",
    ".png": "PNG Image",
    ".txt": "Text or unknown format (heuristic)"
}


# EXTRACT FILE METADATA
def extract_metadata(file_path):
    file_info = file_path.stat()

    metadata = {
        "File Name": file_path.name,
        "Extension": file_path.suffix,
        "File Size (Bytes)": file_info.st_size,

        "Modified Time": datetime.fromtimestamp(
            file_info.st_mtime
        ).astimezone().isoformat(),

        "Accessed Time": datetime.fromtimestamp(
            file_info.st_atime
        ).astimezone().isoformat()
    }

    # Get creation time where available
    birth_time = getattr(file_info, "st_birthtime", None)

    if birth_time is not None:
        creation_time = birth_time
    elif platform.system() == "Windows":
        creation_time = file_info.st_ctime
    else:
        creation_time = None

    if creation_time is not None:
        metadata["Creation Time"] = datetime.fromtimestamp(
            creation_time
        ).astimezone().isoformat()
    else:
        metadata["Creation Time"] = "Not available"

    return metadata


# ANALYSE EVIDENCE
print("DIGITAL FORENSICS - FILE ANALYSIS")
print("=================================")

all_results = []

for file_path in evidence_folder.iterdir():

    if file_path.is_file():

        file_hash = calculate_sha256(file_path)
        actual_type = detect_file_type(file_path)

        expected_type = expected_types.get(
            file_path.suffix.lower()
        )

        metadata = extract_metadata(file_path)

        # Check file extension
        if expected_type and actual_type != expected_type:
            warning = "Possible extension mismatch"
        else:
            warning = "No mismatch detected"

        # Display analysis results
        print("\nFile:", file_path.name)
        print("Size:", file_path.stat().st_size, "bytes")
        print("SHA-256:", file_hash)
        print("Detected type:", actual_type)

        print("\nFILE METADATA")

        for key, value in metadata.items():
            print(key, ":", value)

        print("Extension check:", warning)
        print("---------------------------------")


        # COLLECT RESULTS FOR REPORTS
        result = {
            "SHA-256": file_hash,
            "Detected Type": actual_type,
            "Extension Check": warning
        }

        result.update(metadata)

        all_results.append(result)


# GENERATE CSV REPORT
csv_path = reports_folder / "file_analysis_report.csv"

if all_results:
    with open(
        csv_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        fieldnames = list(all_results[0].keys())

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(all_results)

else:
    print("\nNo evidence files found. CSV report was not generated.")


# GENERATE JSON REPORT
json_path = reports_folder / "file_analysis_report.json"

with open(json_path, "w", encoding="utf-8") as json_file:
    json.dump(all_results, json_file, indent=4)


# FINAL MESSAGE
print("\n=================================")
print("ANALYSIS COMPLETED SUCCESSFULLY!")

if all_results:
    print("CSV report saved:", csv_path)

print("JSON report saved:", json_path)
print("Total files analysed:", len(all_results))
print("=================================")
    