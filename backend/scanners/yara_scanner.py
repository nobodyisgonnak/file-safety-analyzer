from pathlib import Path

try:
    import yara
except ImportError:
    yara = None


def scan_with_yara(
    file_path: Path,
    rules_path: Path,
) -> dict:
    if yara is None:
        return {
            "available": False,
            "detected": False,
            "matches": [],
            "scanner": "YARA",
            "message": "yara-python is not installed.",
        }

    if not rules_path.exists():
        return {
            "available": False,
            "detected": False,
            "matches": [],
            "scanner": "YARA",
            "message": "YARA rules file was not found.",
        }

    try:
        rules = yara.compile(
            filepath=str(rules_path)
        )

        matches = rules.match(
            str(file_path),
            timeout=30,
        )

        match_names = [
            match.rule
            for match in matches
        ]

        return {
            "available": True,
            "detected": bool(match_names),
            "matches": match_names,
            "scanner": "YARA",
            "message": (
                "YARA rules matched suspicious patterns."
                if match_names
                else "No configured YARA rules matched."
            ),
        }

    except yara.TimeoutError:
        return {
            "available": True,
            "detected": False,
            "matches": [],
            "scanner": "YARA",
            "message": "YARA scan timed out.",
        }

    except Exception as exc:
        return {
            "available": False,
            "detected": False,
            "matches": [],
            "scanner": "YARA",
            "message": f"YARA scan failed: {exc}",
        }