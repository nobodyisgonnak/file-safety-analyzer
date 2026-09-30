from pathlib import Path
import hashlib
import mimetypes
import os
import uuid
import zipfile

import magic
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from backend.scanners.clamav_scanner import scan_with_clamav
from backend.scanners.yara_scanner import scan_with_yara


APP_VERSION = "3.0.0"

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
RULES_DIR = BASE_DIR / "backend" / "rules"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 50 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".hta",
}


SUSPICIOUS_MIME_TYPES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable",
}


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".docx",
    ".xlsx",
    ".pptx",
}


KNOWN_MIME_TYPES = {
    ".txt": {
        "text/plain",
    },
    ".pdf": {
        "application/pdf",
    },
    ".jpg": {
        "image/jpeg",
    },
    ".jpeg": {
        "image/jpeg",
    },
    ".png": {
        "image/png",
    },
    ".gif": {
        "image/gif",
    },
    ".zip": {
        "application/zip",
        "application/x-zip-compressed",
    },
    ".docx": {
        "application/zip",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },
    ".xlsx": {
        "application/zip",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
    ".pptx": {
        "application/zip",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    },
    ".exe": {
        "application/x-dosexec",
        "application/x-msdownload",
        "application/vnd.microsoft.portable-executable",
    },
}


def get_allowed_origins() -> list[str]:
    """
    Production frontend URL can be supplied through:
    FRONTEND_URL=https://example.com

    Multiple origins can be separated with commas.
    """
    configured = os.getenv("FRONTEND_URL", "").strip()

    if configured:
        return [
            origin.strip().rstrip("/")
            for origin in configured.split(",")
            if origin.strip()
        ]

    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ]


app = FastAPI(
    title="File Safety Analyzer API",
    version=APP_VERSION,
    description=(
        "Privacy-first file safety and malware analysis API. "
        "Performs static file checks, ClamAV scanning, "
        "and YARA-based suspicious pattern detection."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


def get_risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def get_recommendation(level: str) -> str:
    if level == "HIGH":
        return "Avoid opening this file."

    if level == "MEDIUM":
        return "Use caution before opening this file."

    return "No obvious risk detected."


def extension_matches_mime(
    extension: str,
    mime_type: str,
) -> bool:
    expected_types = KNOWN_MIME_TYPES.get(extension.lower())

    if not expected_types:
        return True

    return mime_type in expected_types


def inspect_archive(file_path: Path):
    findings = []
    suspicious_found = False
    file_count = 0

    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            members = archive.infolist()

            file_count = len(members)

            for member in members:
                if member.is_dir():
                    continue

                inner_name = Path(member.filename)
                inner_extension = inner_name.suffix.lower()

                if inner_extension in SUSPICIOUS_EXTENSIONS:
                    suspicious_found = True

                    findings.append(
                        "Archive contains a suspicious file type: "
                        f"{inner_extension}"
                    )

    except zipfile.BadZipFile:
        findings.append(
            "File has an archive-like extension but is not a valid ZIP archive."
        )

    except Exception as exc:
        findings.append(
            f"Archive inspection could not be completed: {exc}"
        )

    return (
        findings,
        file_count,
        suspicious_found,
    )


def calculate_final_score(
    base_score: int,
    clamav_detected: bool,
    yara_malware_matches: list[str],
) -> int:
    score = base_score

    if clamav_detected:
        score = max(score, 90)

    if yara_malware_matches:
        score += min(
            len(yara_malware_matches) * 20,
            40,
        )

    return min(score, 100)


def classify_yara_matches(
    matches: list[str],
) -> tuple[list[str], list[str]]:
    """
    Windows_PE_File means the file is a Windows PE executable.

    A PE executable is not automatically malware, so it is reported
    as an indicator instead of a malware detection.
    """

    indicator_rules = {
        "Windows_PE_File",
    }

    malware_matches = []
    indicator_matches = []

    for match in matches:
        if match in indicator_rules:
            indicator_matches.append(match)
        else:
            malware_matches.append(match)

    return malware_matches, indicator_matches


@app.get("/")
def root():
    return {
        "message": "File Safety Analyzer backend is running.",
        "version": APP_VERSION,
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": APP_VERSION,
    }


@app.post("/analyze")
async def analyze_file(
    file: UploadFile = File(...),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required.",
        )

    original_filename = Path(file.filename).name

    if not original_filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    extension = Path(original_filename).suffix.lower()

    temp_filename = f"{uuid.uuid4().hex}.upload"
    temp_path = UPLOAD_DIR / temp_filename

    sha256 = hashlib.sha256()
    total_size = 0

    try:
        with temp_path.open("wb") as output_file:

            while True:
                chunk = await file.read(CHUNK_SIZE)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                    
                            "File is too large. Maximum allowed size is 50 MB."
                        ),
                    )

                sha256.update(chunk)
                output_file.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        file_hash = sha256.hexdigest()

        try:
            mime_type = magic.from_file(
                str(temp_path),
                mime=True,
            )

        except Exception:
            mime_type = (
                mimetypes.guess_type(original_filename)[0]
                or "application/octet-stream"
            )

        findings = []
        score = 0

        # -----------------------------------------
        # Extension analysis
        # -----------------------------------------

        if extension in SUSPICIOUS_EXTENSIONS:
            score += 40

            findings.append(
                "File extension may represent an executable "
                f"or script: {extension}"
            )

        # -----------------------------------------
        # MIME analysis
        # -----------------------------------------

        if mime_type in SUSPICIOUS_MIME_TYPES:
            score += 40

            findings.append(
                "Detected MIME type may represent an executable file: "
                f"{mime_type}"
            )

        # -----------------------------------------
        # Extension / MIME mismatch
        # -----------------------------------------

        extension_mismatch = not extension_matches_mime(
            extension,
            mime_type,
        )

        if extension_mismatch:
            score += 30

            findings.append(
                "File extension does not match its detected file type."
            )

        elif extension:
            findings.append(
                "File extension matches its detected file type."
            )

        # -----------------------------------------
        # Archive analysis
        # -----------------------------------------

        archive_file_count = 0
        archive_contains_suspicious_file = False

        if extension in ARCHIVE_EXTENSIONS:

            (
                archive_findings,
                archive_file_count,
                archive_contains_suspicious_file,
            ) = inspect_archive(temp_path)

            findings.extend(archive_findings)

            if archive_contains_suspicious_file:
                score += 30

        # -----------------------------------------
        # PDF validation
        # -----------------------------------------

        if extension == ".pdf":

            try:
                with temp_path.open("rb") as pdf_file:
                    header = pdf_file.read(5)

                if header == b"%PDF-":
                    findings.append(
                        "PDF header is valid."
                    )

                else:
                    score += 30

                    findings.append(
                        "PDF header is invalid or missing."
                    )

            except Exception:
                score += 30

                findings.append(
                    "PDF structure could not be checked."
                )

        # -----------------------------------------
        # ClamAV
        # -----------------------------------------

        clamav_result = scan_with_clamav(
            temp_path
        )

        if clamav_result["detected"]:

            findings.append(
                "ClamAV detected a known malware signature."
            )

        elif clamav_result.get("scan_ok"):

            findings.append(
                "ClamAV scan completed without "
                "detecting known malware."
            )

        elif clamav_result["available"]:

            findings.append(
                "ClamAV was available but the scan "
                "could not be completed successfully."
            )

        else:

            findings.append(
                "ClamAV scan was unavailable."
            )

        # -----------------------------------------
        # YARA
        # -----------------------------------------

        yara_rules_path = (
            RULES_DIR / "malware_rules.yar"
        )

        yara_result = scan_with_yara(
            temp_path,
            yara_rules_path,
        )

        yara_matches = yara_result.get(
            "matches",
            [],
        )

        (
            yara_malware_matches,
            yara_indicator_matches,
        ) = classify_yara_matches(
            yara_matches
        )

        if yara_malware_matches:

            findings.append(
                "YARA matched suspicious malware-related "
                f"rule(s): {', '.join(yara_malware_matches)}"
            )

        if yara_indicator_matches:

            findings.append(
                "YARA identified file characteristics: "
                f"{', '.join(yara_indicator_matches)}"
            )

        if (
            not yara_matches
            and yara_result["available"]
            and yara_result.get("scan_ok", False)
        ):

            findings.append(
                "YARA scan completed without "
                "matching configured rules."
            )

        elif not yara_result["available"]:

            findings.append(
                "YARA scan was unavailable."
            )

        elif yara_result.get("scan_ok") is False:

            findings.append(
                "YARA scan could not be completed successfully."
            )

        # -----------------------------------------
        # Final risk calculation
        # -----------------------------------------

        risk_score = calculate_final_score(
            base_score=score,
            clamav_detected=clamav_result["detected"],
            yara_malware_matches=yara_malware_matches,
        )

        risk_level = get_risk_level(
            risk_score
        )

        recommendation = get_recommendation(
            risk_level
        )

        malware_detected = (
            clamav_result["detected"]
            or bool(yara_malware_matches)
        )

        # -----------------------------------------
        # API response
        # -----------------------------------------

        return {
            "filename": original_filename,
            "size": total_size,
            "sha256": file_hash,
            "mime_type": mime_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendation": recommendation,
            "findings": findings,
            "extension_mismatch": extension_mismatch,
            "archive_file_count": archive_file_count,
            "archive_contains_suspicious_file": (
                archive_contains_suspicious_file
            ),
            "malware_detection": {
                "detected": malware_detected,
                "clamav": clamav_result,
                "yara": {
                    **yara_result,
                    "malware_matches": yara_malware_matches,
                    "indicator_matches": yara_indicator_matches,
                },
            },
        }

    finally:

        try:
            await file.close()

        except Exception:
            pass

        try:
            if temp_path.exists():
                temp_path.unlink()

        except Exception:
            pass