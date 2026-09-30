from pathlib import Path
import os
import shutil
import subprocess


DEFAULT_CLAMAV_PATHS = [
    Path(r"C:\Program Files\ClamAV\clamscan.exe"),
    Path(r"C:\Program Files (x86)\ClamAV\clamscan.exe"),
]


def find_clamscan() -> str | None:
    """
    Finds clamscan using:

    1. CLAMSCAN_PATH environment variable
    2. System PATH
    3. Common Windows installation locations
    """

    configured_path = os.getenv("CLAMSCAN_PATH")

    if configured_path:
        configured = Path(configured_path)

        if configured.exists():
            return str(configured)

    path_result = shutil.which("clamscan")

    if path_result:
        return path_result

    for candidate in DEFAULT_CLAMAV_PATHS:

        if candidate.exists():
            return str(candidate)

    return None


def parse_clamav_output(
    output: str,
) -> str | None:

    for line in output.splitlines():

        if " FOUND" in line:
            return line.strip()

    return None


def scan_with_clamav(
    file_path: Path,
) -> dict:

    clamscan_path = find_clamscan()

    if not clamscan_path:

        return {
            "available": False,
            "scan_ok": False,
            "detected": False,
            "scanner": "ClamAV",
            "message": (
                "clamscan executable was not found."
            ),
        }

    try:

        creationflags = 0

        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(
            [
                clamscan_path,
                "--no-summary",
                str(file_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=creationflags,
        )

        combined_output = (
            (result.stdout or "")
            + "\n"
            + (result.stderr or "")
        ).strip()

        detection = parse_clamav_output(
            combined_output
        )

        # ClamAV:
        # 0 = no virus found
        # 1 = virus found
        # Other = error

        if result.returncode == 0:

            return {
                "available": True,
                "scan_ok": True,
                "detected": False,
                "scanner": "ClamAV",
                "return_code": result.returncode,
                "message": (
                    "No known malware detected."
                ),
            }

        if result.returncode == 1:

            return {
                "available": True,
                "scan_ok": True,
                "detected": True,
                "scanner": "ClamAV",
                "return_code": result.returncode,
                "message": (
                    detection
                    or "ClamAV detected a threat."
                ),
            }

        return {
            "available": True,
            "scan_ok": False,
            "detected": False,
            "scanner": "ClamAV",
            "return_code": result.returncode,
            "message": (
                "ClamAV scan failed."
            ),
        }

    except subprocess.TimeoutExpired:

        return {
            "available": True,
            "scan_ok": False,
            "detected": False,
            "scanner": "ClamAV",
            "message": (
                "ClamAV scan timed out."
            ),
        }

    except Exception as exc:

        return {
            "available": True,
            "scan_ok": False,
            "detected": False,
            "scanner": "ClamAV",
            "message": (
                f"ClamAV scan failed: {exc}"
            ),
        }